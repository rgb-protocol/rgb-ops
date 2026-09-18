// RGB ops library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2024 by
//     Zoe Faltibà <zoefaltiba@gmail.com>
// Rewritten in 2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{HashMap, HashSet};
use std::iter;
use std::num::NonZeroU32;

use amplify::hex::FromHex;
pub use electrum_client;
use electrum_client::{Batch, Client, ElectrumApi, Error as ElectrumError, Param};
use rgb::bitcoin::constants::ChainHash;
use rgb::bitcoin::{consensus, Transaction as Tx, Txid};
use rgbcore::validation::{ResolveWitness, WitnessResolverError, WitnessStatus};
use rgbcore::vm::{WitnessOrd, WitnessPos};
use rgbcore::ChainNet;

const MISSING_TRANSACTION_ERROR: &str = "No such mempool or blockchain transaction";

struct ConfirmedWitness {
    tx: Tx,
    block_time: i64,
    expected_height: usize,
}

/// Wrapper of an electrum client, necessary to implement the foreign `ResolveWitness` trait.
pub struct ElectrumClient {
    pub inner: Client,
}

impl ElectrumClient {
    fn resolver_error(txid: Option<Txid>, error: impl ToString) -> WitnessResolverError {
        WitnessResolverError::ResolverIssue(txid, error.to_string())
    }

    fn transaction_missing(error: &ElectrumError) -> bool {
        error.to_string().contains(MISSING_TRANSACTION_ERROR)
    }

    fn batch_verbose_transactions(
        inner: &Client,
        witness_ids: &[Txid],
    ) -> Result<HashMap<Txid, Option<serde_json::Value>>, WitnessResolverError> {
        let mut responses = HashMap::with_capacity(witness_ids.len());
        let mut batch = Batch::default();
        for witness_id in witness_ids {
            batch.raw(s!("blockchain.transaction.get"), vec![
                Param::String(witness_id.to_string()),
                Param::Bool(true),
            ]);
        }

        let values = inner
            .batch_call(&batch)
            .map_err(|error| Self::resolver_error(None, error))?;
        if values.len() != witness_ids.len() {
            return Err(WitnessResolverError::InvalidResolverData);
        }

        for (witness_id, value) in witness_ids.iter().copied().zip(values) {
            if !value.is_null() {
                responses.insert(witness_id, Some(value));
                continue;
            }

            // electrum-client represents an individual JSON-RPC error inside a
            // successful batch as `null`. Replay only that exceptional item so
            // a missing transaction remains `Unresolved` while transport and
            // protocol errors retain their normal typed failure semantics.
            match inner.raw_call("blockchain.transaction.get", vec![
                Param::String(witness_id.to_string()),
                Param::Bool(true),
            ]) {
                Ok(value) if !value.is_null() => {
                    responses.insert(witness_id, Some(value));
                }
                Ok(_) => return Err(WitnessResolverError::InvalidResolverData),
                Err(error) if Self::transaction_missing(&error) => {
                    responses.insert(witness_id, None);
                }
                Err(error) => return Err(Self::resolver_error(Some(witness_id), error)),
            }
        }

        Ok(responses)
    }

    fn parse_verbose_transaction(
        witness_id: Txid,
        tx_details: &serde_json::Value,
        tip_height: usize,
    ) -> Result<Result<ConfirmedWitness, Tx>, WitnessResolverError> {
        let Some(tx_hex) = tx_details
            .get("hex")
            .and_then(|value| value.as_str())
            .and_then(|value| Vec::<u8>::from_hex(value).ok())
        else {
            return Err(WitnessResolverError::InvalidResolverData);
        };
        let tx: Tx = consensus::deserialize(&tx_hex)
            .map_err(|_| WitnessResolverError::InvalidResolverData)?;
        if tx.compute_txid() != witness_id {
            return Err(WitnessResolverError::InvalidResolverData);
        }

        let Some(confirmations) = tx_details.get("confirmations") else {
            return Ok(Err(tx));
        };
        let confirmations = confirmations
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(WitnessResolverError::InvalidResolverData)?;
        if confirmations == 0 {
            return Ok(Err(tx));
        }

        let block_time = tx_details
            .get("blocktime")
            .and_then(|value| value.as_i64())
            .ok_or(WitnessResolverError::InvalidResolverData)?;
        let expected_height = Self::confirmed_height(tip_height, confirmations)?;

        Ok(Ok(ConfirmedWitness {
            tx,
            block_time,
            expected_height,
        }))
    }

    fn confirmed_height(
        tip_height: usize,
        confirmations: usize,
    ) -> Result<usize, WitnessResolverError> {
        tip_height
            .checked_add(1)
            .and_then(|height| height.checked_sub(confirmations))
            .ok_or(WitnessResolverError::InvalidResolverData)
    }

    fn resolve_witness_with(
        inner: &Client,
        txid: Txid,
    ) -> Result<WitnessStatus, WitnessResolverError> {
        // We get the height of the tip of blockchain
        let header = inner
            .block_headers_subscribe()
            .map_err(|e| WitnessResolverError::ResolverIssue(Some(txid), e.to_string()))?;

        // Now we get and parse transaction information to get the number of
        // confirmations
        let tx_details = match inner.raw_call("blockchain.transaction.get", vec![
            Param::String(txid.to_string()),
            Param::Bool(true),
        ]) {
            Err(e) if e.to_string().contains(MISSING_TRANSACTION_ERROR) => {
                return Ok(WitnessStatus::Unresolved);
            }
            Err(e) => return Err(WitnessResolverError::ResolverIssue(Some(txid), e.to_string())),
            Ok(v) => v,
        };
        let forward = iter::from_fn(|| inner.block_headers_pop().ok().flatten()).count() as isize;

        let Some(tx_hex) = tx_details
            .get("hex")
            .and_then(|v| v.as_str())
            .and_then(|s| Vec::<u8>::from_hex(s).ok())
        else {
            return Err(WitnessResolverError::InvalidResolverData);
        };
        let tx: Tx = consensus::deserialize(&tx_hex)
            .map_err(|_| WitnessResolverError::InvalidResolverData)?;

        let Some(confirmations) = tx_details.get("confirmations") else {
            return Ok(WitnessStatus::Resolved(tx, WitnessOrd::Tentative));
        };
        let confirmations = confirmations
            .as_u64()
            .and_then(|x| u32::try_from(x).ok())
            .ok_or(WitnessResolverError::InvalidResolverData)?;
        if confirmations == 0 {
            return Ok(WitnessStatus::Resolved(tx, WitnessOrd::Tentative));
        }
        let block_time = tx_details
            .get("blocktime")
            .and_then(|v| v.as_i64())
            .ok_or(WitnessResolverError::InvalidResolverData)?;

        let tip_height =
            u32::try_from(header.height).map_err(|_| WitnessResolverError::InvalidResolverData)?;
        let height: isize = (tip_height - confirmations) as isize;
        const SAFETY_MARGIN: isize = 1;
        // first check from expected min to max height
        let get_merkle_res = (1..=forward + 1)
            // we need this under assumption that electrum was lying due to "DB desynchronization"
            // since this have a very low probability we do that after everything else
            .chain((1..=SAFETY_MARGIN).flat_map(|i| [i + forward + 1, 1 - i]))
            .find_map(|offset| {
                inner
                    .transaction_get_merkle(&txid, (height + offset) as usize)
                    .ok()
            })
            .ok_or_else(|| {
                WitnessResolverError::ResolverIssue(
                    Some(txid),
                    s!("transaction can't be located in the blockchain"),
                )
            })?;

        let tx_height = u32::try_from(get_merkle_res.block_height)
            .map_err(|_| WitnessResolverError::InvalidResolverData)?;

        let height = NonZeroU32::new(tx_height).ok_or(WitnessResolverError::InvalidResolverData)?;
        let pos = WitnessPos::bitcoin(height, block_time)
            .ok_or(WitnessResolverError::InvalidResolverData)?;

        Ok(WitnessStatus::Resolved(tx, WitnessOrd::Mined(pos)))
    }
}

impl ResolveWitness for ElectrumClient {
    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        // check the electrum server is for the correct network
        let block_hash = self
            .inner
            .block_header(0)
            .map_err(|e| WitnessResolverError::ResolverIssue(None, e.to_string()))?
            .block_hash();
        let chain_hash = ChainHash::from_genesis_block_hash(block_hash);
        if chain_net.chain_hash() != chain_hash {
            return Err(WitnessResolverError::WrongChainNet);
        }
        // check the electrum server has the required functionality (verbose
        // transactions)
        let txid = match chain_net {
            ChainNet::BitcoinMainnet => {
                Some("33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036")
            }
            ChainNet::BitcoinTestnet3 => {
                Some("5e6560fd518aadbed67ee4a55bdc09f19e619544f5511e9343ebba66d2f62653")
            }
            ChainNet::BitcoinTestnet4 => {
                Some("7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e")
            }
            ChainNet::BitcoinSignet => {
                Some("8153034f45e695453250a8fb7225a5e545144071d8ed7b0d3211efa1f3c92ad8")
            }
            ChainNet::BitcoinSignetCustom => None,
            ChainNet::BitcoinRegtest => {
                Some("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
            }
            _ => return Err(WitnessResolverError::WrongChainNet),
        };
        let txid = if let Some(txid) = txid {
            txid.to_string()
        } else {
            self.inner
                .raw_call("blockchain.transaction.id_from_pos", vec![
                    Param::Usize(1),
                    Param::Usize(0),
                    Param::Bool(false),
                ])
                .map_err(|e| WitnessResolverError::ResolverIssue(None, e.to_string()))?
                .get("tx_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or(WitnessResolverError::InvalidResolverData)?
        };
        // check the transaction can be fetched before probing verbose support
        if let Err(e) = self.inner.raw_call("blockchain.transaction.get", vec![
            Param::String(txid.clone()),
            Param::Bool(false),
        ]) {
            if !e
                .to_string()
                .contains("genesis block coinbase is not considered an ordinary transaction")
            {
                return Err(WitnessResolverError::WrongChainNet);
            }
        }
        if let Err(e) = self
            .inner
            .raw_call("blockchain.transaction.get", vec![Param::String(txid), Param::Bool(true)])
        {
            if !e
                .to_string()
                .contains("genesis block coinbase is not considered an ordinary transaction")
            {
                return Err(WitnessResolverError::ResolverIssue(
                    None,
                    s!("verbose transactions are unsupported by the provided electrum service"),
                ));
            }
        }
        Ok(())
    }

    fn resolve_witness(&self, txid: Txid) -> Result<WitnessStatus, WitnessResolverError> {
        Self::resolve_witness_with(&self.inner, txid)
    }
}

impl ElectrumClient {
    /// Resolve witness transactions using native Electrum request batches.
    ///
    /// Duplicate transaction IDs are resolved once. If a server does not
    /// support either batch operation, resolution falls back to the existing
    /// serial path without changing witness semantics.
    pub fn resolve_witnesses(
        &self,
        witness_ids: &[Txid],
    ) -> Result<HashMap<Txid, WitnessStatus>, WitnessResolverError> {
        resolve_witnesses(&self.inner, witness_ids)
    }
}

/// Resolve witness transactions using native Electrum request batches on an
/// existing client connection.
///
/// This function does not retain results beyond the call. Duplicate
/// transaction IDs are resolved once, and failed batch operations fall back to
/// the existing serial resolver.
pub fn resolve_witnesses(
    inner: &Client,
    witness_ids: &[Txid],
) -> Result<HashMap<Txid, WitnessStatus>, WitnessResolverError> {
    let mut unique_ids = Vec::with_capacity(witness_ids.len());
    let mut seen = HashSet::with_capacity(witness_ids.len());
    for witness_id in witness_ids {
        if seen.insert(*witness_id) {
            unique_ids.push(*witness_id);
        }
    }
    if unique_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let header = inner
        .block_headers_subscribe()
        .map_err(|error| ElectrumClient::resolver_error(None, error))?;
    let tx_details = match ElectrumClient::batch_verbose_transactions(inner, &unique_ids) {
        Ok(tx_details) => tx_details,
        Err(_) => {
            return unique_ids
                .into_iter()
                .map(|witness_id| {
                    ElectrumClient::resolve_witness_with(inner, witness_id)
                        .map(|status| (witness_id, status))
                })
                .collect();
        }
    };
    let forwarded_headers = iter::from_fn(|| inner.block_headers_pop().ok().flatten()).count();
    let tip_height = header
        .height
        .checked_add(forwarded_headers)
        .ok_or(WitnessResolverError::InvalidResolverData)?;

    let mut witnesses = HashMap::with_capacity(unique_ids.len());
    let mut confirmed = Vec::new();
    for witness_id in unique_ids {
        let Some(details) = tx_details.get(&witness_id) else {
            return Err(WitnessResolverError::InvalidResolverData);
        };
        let Some(details) = details else {
            witnesses.insert(witness_id, WitnessStatus::Unresolved);
            continue;
        };

        match ElectrumClient::parse_verbose_transaction(witness_id, details, tip_height)? {
            Ok(confirmed_witness) => confirmed.push((witness_id, confirmed_witness)),
            Err(tx) => {
                witnesses.insert(witness_id, WitnessStatus::Resolved(tx, WitnessOrd::Tentative));
            }
        }
    }

    let merkle_requests = confirmed
        .iter()
        .map(|(witness_id, witness)| (*witness_id, witness.expected_height))
        .collect::<Vec<_>>();
    let merkle_responses = match inner.batch_transaction_get_merkle(&merkle_requests) {
        Ok(responses) if responses.len() == merkle_requests.len() => responses,
        Ok(_) => return Err(WitnessResolverError::InvalidResolverData),
        Err(_) => {
            for (witness_id, _) in confirmed {
                witnesses
                    .insert(witness_id, ElectrumClient::resolve_witness_with(inner, witness_id)?);
            }
            return Ok(witnesses);
        }
    };

    for ((witness_id, confirmed_witness), merkle_response) in
        confirmed.into_iter().zip(merkle_responses)
    {
        if merkle_response.block_height != confirmed_witness.expected_height {
            witnesses.insert(witness_id, ElectrumClient::resolve_witness_with(inner, witness_id)?);
            continue;
        }
        let block_height = u32::try_from(merkle_response.block_height)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(WitnessResolverError::InvalidResolverData)?;
        let position = WitnessPos::bitcoin(block_height, confirmed_witness.block_time)
            .ok_or(WitnessResolverError::InvalidResolverData)?;
        witnesses.insert(
            witness_id,
            WitnessStatus::Resolved(confirmed_witness.tx, WitnessOrd::Mined(position)),
        );
    }

    Ok(witnesses)
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use amplify::hex::ToHex;
    use rgb::bitcoin::absolute::LockTime;
    use rgb::bitcoin::transaction::Version;
    use rgb::bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    use super::*;

    #[test]
    fn confirmed_height_uses_tip_and_confirmation_count() {
        assert_eq!(ElectrumClient::confirmed_height(1_000, 17).unwrap(), 984);
        assert!(ElectrumClient::confirmed_height(10, 12).is_err());
    }

    #[test]
    fn missing_transaction_detection_is_specific() {
        let missing = ElectrumError::Message(MISSING_TRANSACTION_ERROR.to_owned());
        let transport = ElectrumError::Message(s!("connection reset"));

        assert!(ElectrumClient::transaction_missing(&missing));
        assert!(!ElectrumClient::transaction_missing(&transport));
    }

    #[test]
    fn verbose_transaction_requires_the_requested_identity() {
        let tx = test_transaction(1);
        let details = serde_json::json!({
            "hex": consensus::serialize(&tx).to_hex(),
            "confirmations": 1,
            "blocktime": 1_700_000_000,
        });

        assert!(matches!(
            ElectrumClient::parse_verbose_transaction(
                test_transaction(2).compute_txid(),
                &details,
                120,
            ),
            Err(WitnessResolverError::InvalidResolverData)
        ));
    }

    #[test]
    fn verbose_unconfirmed_transaction_is_tentative() {
        let tx = test_transaction(1);
        let details = serde_json::json!({
            "hex": consensus::serialize(&tx).to_hex(),
        });

        let parsed =
            ElectrumClient::parse_verbose_transaction(tx.compute_txid(), &details, 120).unwrap();
        let Err(parsed_tx) = parsed else {
            panic!("expected a tentative transaction");
        };
        assert_eq!(parsed_tx, tx);
    }

    #[test]
    fn resolves_confirmed_witnesses_in_two_batches() {
        let txes = [test_transaction(1), test_transaction(2)];
        let txids = txes.iter().map(Tx::compute_txid).collect::<Vec<_>>();
        let tx_hex = txes
            .iter()
            .map(|tx| consensus::serialize(tx).to_hex())
            .collect::<Vec<_>>();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;

            let version = read_request(&mut reader);
            assert_eq!(version["method"], "server.version");
            write_result(&mut writer, &version, serde_json::json!(["test", "1.4"]));

            let header = read_request(&mut reader);
            assert_eq!(header["method"], "blockchain.headers.subscribe");
            write_result(
                &mut writer,
                &header,
                serde_json::json!({
                    "height": 120,
                    "hex": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                }),
            );

            let transaction_requests = [read_request(&mut reader), read_request(&mut reader)];
            for request in &transaction_requests {
                assert_eq!(request["method"], "blockchain.transaction.get");
            }
            for (index, request) in transaction_requests.iter().enumerate().rev() {
                write_result(
                    &mut writer,
                    request,
                    serde_json::json!({
                        "hex": tx_hex[index],
                        "confirmations": if index == 0 { 21 } else { 11 },
                        "blocktime": 1_700_000_000 + index as i64,
                    }),
                );
            }

            let merkle_requests = [read_request(&mut reader), read_request(&mut reader)];
            for request in &merkle_requests {
                assert_eq!(request["method"], "blockchain.transaction.get_merkle");
            }
            let mut heights = merkle_requests
                .iter()
                .map(|request| request["params"][1].as_u64().unwrap())
                .collect::<Vec<_>>();
            heights.sort_unstable();
            assert_eq!(heights, [100, 110]);
            for request in merkle_requests.iter().rev() {
                write_result(
                    &mut writer,
                    request,
                    serde_json::json!({
                        "block_height": request["params"][1],
                        "pos": 0,
                        "merkle": [],
                    }),
                );
            }
        });

        let client = ElectrumClient {
            inner: Client::new(&format!("tcp://{address}")).unwrap(),
        };
        let witnesses = client
            .resolve_witnesses(&[txids[0], txids[0], txids[1]])
            .unwrap();

        assert_eq!(witnesses.len(), 2);
        for (txid, tx) in txids.into_iter().zip(txes.iter()) {
            let WitnessStatus::Resolved(resolved, WitnessOrd::Mined(_)) = &witnesses[&txid] else {
                panic!("expected a mined witness");
            };
            assert_eq!(resolved, tx);
        }
        server.join().unwrap();
    }

    #[test]
    fn isolates_missing_transactions_without_losing_batch_results() {
        let txes = [test_transaction(1), test_transaction(2)];
        let txids = txes.iter().map(Tx::compute_txid).collect::<Vec<_>>();
        let tx_hex = txes
            .iter()
            .map(|tx| consensus::serialize(tx).to_hex())
            .collect::<Vec<_>>();
        let missing_txid = test_transaction(3).compute_txid();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_txids = txids.clone();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;

            let version = read_request(&mut reader);
            write_result(&mut writer, &version, serde_json::json!(["test", "1.4"]));

            let header = read_request(&mut reader);
            write_result(
                &mut writer,
                &header,
                serde_json::json!({
                    "height": 120,
                    "hex": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                }),
            );

            respond_transaction_batch(
                &mut reader,
                &mut writer,
                3,
                &server_txids,
                &tx_hex,
                missing_txid,
            );
            respond_transaction_batch(
                &mut reader,
                &mut writer,
                1,
                &server_txids,
                &tx_hex,
                missing_txid,
            );

            let merkle_requests = [read_request(&mut reader), read_request(&mut reader)];
            for request in merkle_requests.iter().rev() {
                write_result(
                    &mut writer,
                    request,
                    serde_json::json!({
                        "block_height": request["params"][1],
                        "pos": 0,
                        "merkle": [],
                    }),
                );
            }
        });

        let client = ElectrumClient {
            inner: Client::new(&format!("tcp://{address}")).unwrap(),
        };
        let witnesses = client
            .resolve_witnesses(&[txids[0], missing_txid, txids[1]])
            .unwrap();

        assert_eq!(witnesses.len(), 3);
        assert!(matches!(witnesses[&missing_txid], WitnessStatus::Unresolved));
        for txid in txids {
            assert!(matches!(witnesses[&txid], WitnessStatus::Resolved(_, WitnessOrd::Mined(_))));
        }
        server.join().unwrap();
    }

    #[test]
    fn batch_protocol_error_preserves_serial_missing_semantics() {
        let missing_txid = test_transaction(3).compute_txid();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;

            let version = read_request(&mut reader);
            write_result(&mut writer, &version, serde_json::json!(["test", "1.4"]));

            let batch_header = read_request(&mut reader);
            write_header(&mut writer, &batch_header);

            let batch_transaction = read_request(&mut reader);
            assert_eq!(batch_transaction["method"], "blockchain.transaction.get");
            write_error(&mut writer, &batch_transaction);

            let serial_header = read_request(&mut reader);
            write_header(&mut writer, &serial_header);

            let serial_transaction = read_request(&mut reader);
            assert_eq!(serial_transaction["method"], "blockchain.transaction.get");
            write_error(&mut writer, &serial_transaction);
        });

        let client = ElectrumClient {
            inner: Client::new(&format!("tcp://{address}")).unwrap(),
        };
        let witnesses = client.resolve_witnesses(&[missing_txid]).unwrap();

        assert!(matches!(witnesses[&missing_txid], WitnessStatus::Unresolved));
        server.join().unwrap();
    }

    fn test_transaction(value: u64) -> Tx {
        Tx {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn read_request(reader: &mut impl BufRead) -> serde_json::Value {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn write_result(
        writer: &mut impl Write,
        request: &serde_json::Value,
        result: serde_json::Value,
    ) {
        serde_json::to_writer(
            &mut *writer,
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": result,
            }),
        )
        .unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();
    }

    fn write_header(writer: &mut impl Write, request: &serde_json::Value) {
        assert_eq!(request["method"], "blockchain.headers.subscribe");
        write_result(
            writer,
            request,
            serde_json::json!({
                "height": 120,
                "hex": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            }),
        );
    }

    fn write_error(writer: &mut impl Write, request: &serde_json::Value) {
        serde_json::to_writer(
            &mut *writer,
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": {
                    "code": -5,
                    "message": MISSING_TRANSACTION_ERROR,
                },
            }),
        )
        .unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();
    }

    fn respond_transaction_batch(
        reader: &mut impl BufRead,
        writer: &mut impl Write,
        request_count: usize,
        txids: &[Txid],
        tx_hex: &[String],
        missing_txid: Txid,
    ) {
        let requests = (0..request_count)
            .map(|_| read_request(reader))
            .collect::<Vec<_>>();
        for request in requests.iter().rev() {
            assert_eq!(request["method"], "blockchain.transaction.get");
            let requested = request["params"][0].as_str().unwrap();
            if requested == missing_txid.to_string() {
                write_error(writer, request);
                continue;
            }
            let index = txids
                .iter()
                .position(|txid| requested == txid.to_string())
                .unwrap();
            write_result(
                writer,
                request,
                serde_json::json!({
                    "hex": tx_hex[index],
                    "confirmations": if index == 0 { 21 } else { 11 },
                    "blocktime": 1_700_000_000 + index as i64,
                }),
            );
        }
    }
}
