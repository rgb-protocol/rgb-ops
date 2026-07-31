// RGB ops library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

use std::num::NonZeroU32;

use amplify::confinement::Confined;
pub use esplora_client;
use esplora_client::BlockingClient;
use rgb::bitcoin::block::Header;
use rgb::bitcoin::constants::ChainHash;
use rgb::bitcoin::hashes::Hash as _;
use rgb::bitcoin::{TxMerkleNode, Txid};
use rgbcore::validation::{ResolveWitness, SpvProof, WitnessResolverError, WitnessStatus};
use rgbcore::vm::{WitnessOrd, WitnessPos};
use rgbcore::ChainNet;

use crate::indexers::ResolveSpvProof;

/// Wrapper of an esplora client, necessary to implement the foreign `ResolveWitness` trait.
pub struct EsploraClient {
    pub inner: BlockingClient,
}

impl ResolveWitness for EsploraClient {
    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        // check the esplora server is for the correct network
        let block_hash = self
            .inner
            .get_block_hash(0)
            .map_err(|e| WitnessResolverError::ResolverIssue(None, e.to_string()))?;
        let chain_hash = ChainHash::from_genesis_block_hash(block_hash);
        if chain_net.chain_hash() != chain_hash {
            return Err(WitnessResolverError::WrongChainNet);
        }
        Ok(())
    }

    fn resolve_witness(&self, txid: Txid) -> Result<WitnessStatus, WitnessResolverError> {
        let Some(tx_info) = self
            .inner
            .get_tx_info(&txid)
            .map_err(|e| WitnessResolverError::ResolverIssue(Some(txid), e.to_string()))?
        else {
            return Ok(WitnessStatus::Unresolved);
        };
        let tx = tx_info.to_tx();
        let ord = match tx_info.status.block_height.zip(tx_info.status.block_time) {
            Some((h, t)) => {
                let height = NonZeroU32::new(h).ok_or(WitnessResolverError::InvalidResolverData)?;
                WitnessOrd::Mined(
                    WitnessPos::bitcoin(height, t as i64)
                        .ok_or(WitnessResolverError::InvalidResolverData)?,
                )
            }
            None => WitnessOrd::Tentative,
        };
        Ok(WitnessStatus::Resolved(tx, ord))
    }

    fn get_block_header(&self, height: NonZeroU32) -> Result<Header, WitnessResolverError> {
        // esplora has no height-keyed header endpoint, so the height is first resolved to
        // the hash of the block occupying it in the best chain
        let block_hash = self
            .inner
            .get_block_hash(height.get())
            .map_err(|e| WitnessResolverError::ResolverIssue(None, e.to_string()))?;
        self.inner
            .get_header_by_hash(&block_hash)
            .map_err(|e| WitnessResolverError::ResolverIssue(None, e.to_string()))
    }
}

impl ResolveSpvProof for EsploraClient {
    fn resolve_spv_proof(&self, txid: Txid) -> Result<SpvProof, WitnessResolverError> {
        let proof = self
            .inner
            .get_merkle_proof(&txid)
            .map_err(|e| WitnessResolverError::ResolverIssue(Some(txid), e.to_string()))?
            .ok_or_else(|| {
                WitnessResolverError::ResolverIssue(Some(txid), s!("TX is unknown or not mined"))
            })?;
        let block_height =
            NonZeroU32::new(proof.block_height).ok_or(WitnessResolverError::InvalidResolverData)?;
        let pos =
            u32::try_from(proof.pos).map_err(|_| WitnessResolverError::InvalidResolverData)?;
        // esplora returns merkle path elements as txids, hence already in internal byte order
        let merkle = proof
            .merkle
            .into_iter()
            .map(|node| TxMerkleNode::from_byte_array(node.to_byte_array()))
            .collect::<Vec<_>>();
        let merkle =
            Confined::try_from(merkle).map_err(|_| WitnessResolverError::InvalidResolverData)?;
        Ok(SpvProof {
            block_height,
            pos,
            merkle,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use rgb::bitcoin::{absolute, transaction, Transaction};

    use super::*;

    const BLOCK_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn dumb_tx(version: i32) -> Transaction {
        Transaction {
            version: transaction::Version::non_standard(version),
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    fn dumb_tx_info(txid: Txid, version: i32, status: &str) -> String {
        format!(
            r#"{{"txid":"{txid}","version":{version},"locktime":0,"vin":[],"vout":[],"size":10,"weight":40,"status":{status},"fee":0}}"#
        )
    }

    fn mock_client(status: &str, body: String) -> (EsploraClient, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock Esplora server");
        let address = listener.local_addr().expect("read mock server address");
        let status = status.to_owned();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept Esplora request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set mock server read timeout");
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut buffer = [0_u8; 1024];
                let bytes_read = stream.read(&mut buffer).expect("read Esplora request");
                assert!(bytes_read > 0, "Esplora request ended before its headers");
                request.extend_from_slice(&buffer[..bytes_read]);
            }
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: \
                 {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("write mock Esplora response");
            String::from_utf8(request).expect("Esplora request is UTF-8")
        });
        let url = format!("http://{address}");
        let client = EsploraClient {
            inner: esplora_client::Builder::new(&url)
                .timeout(5)
                .build_blocking(),
        };
        (client, handle)
    }

    fn assert_combined_request(request: JoinHandle<String>, txid: Txid) {
        let request = request.join().expect("join mock Esplora server");
        assert!(request.starts_with(&format!("GET /tx/{txid} HTTP/1.1")));
    }

    #[test]
    fn resolves_confirmed_witness_with_one_combined_request() {
        let tx = dumb_tx(2);
        let txid = tx.compute_txid();
        let status = format!(
            r#"{{"confirmed":true,"block_height":1,"block_hash":"{BLOCK_HASH}","block_time":1231006505}}"#
        );
        let (client, request) = mock_client("200 OK", dumb_tx_info(txid, 2, &status));

        let resolved = client.resolve_witness(txid).expect("resolve witness");

        let position = WitnessPos::bitcoin(NonZeroU32::new(1).unwrap(), 1231006505).unwrap();
        assert_eq!(resolved, WitnessStatus::Resolved(tx, WitnessOrd::Mined(position)));
        assert_combined_request(request, txid);
    }

    #[test]
    fn resolves_unconfirmed_witness_with_one_combined_request() {
        let tx = dumb_tx(2);
        let txid = tx.compute_txid();
        let status =
            r#"{"confirmed":false,"block_height":null,"block_hash":null,"block_time":null}"#;
        let (client, request) = mock_client("200 OK", dumb_tx_info(txid, 2, status));

        let resolved = client.resolve_witness(txid).expect("resolve witness");

        assert_eq!(resolved, WitnessStatus::Resolved(tx, WitnessOrd::Tentative));
        assert_combined_request(request, txid);
    }

    #[test]
    fn returns_unresolved_for_missing_witness() {
        let txid = dumb_tx(2).compute_txid();
        let (client, request) = mock_client("404 Not Found", String::new());

        let resolved = client.resolve_witness(txid).expect("resolve witness");

        assert_eq!(resolved, WitnessStatus::Unresolved);
        assert_combined_request(request, txid);
    }

    #[test]
    fn rejects_zero_confirmation_height() {
        let tx = dumb_tx(2);
        let txid = tx.compute_txid();
        let status = format!(
            r#"{{"confirmed":true,"block_height":0,"block_hash":"{BLOCK_HASH}","block_time":1231006505}}"#
        );
        let (client, request) = mock_client("200 OK", dumb_tx_info(txid, 2, &status));

        let error = client
            .resolve_witness(txid)
            .expect_err("reject invalid height");

        assert_eq!(error, WitnessResolverError::InvalidResolverData);
        assert_combined_request(request, txid);
    }

    #[test]
    fn maps_malformed_response_to_resolver_error() {
        let txid = dumb_tx(2).compute_txid();
        let (client, request) = mock_client("200 OK", "not-json".to_owned());

        let error = client
            .resolve_witness(txid)
            .expect_err("reject malformed response");

        assert!(matches!(
            error,
            WitnessResolverError::ResolverIssue(Some(error_txid), _) if error_txid == txid
        ));
        assert_combined_request(request, txid);
    }
}
