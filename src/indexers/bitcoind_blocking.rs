// RGB ops library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 RGB-Tools developers. All rights reserved.
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
use std::sync::atomic::{AtomicBool, Ordering};

use amplify::confinement::Confined;
pub use bitcoincore_rpc;
use bitcoincore_rpc::{jsonrpc, Client, Error as RpcError, RpcApi};
use rgb::bitcoin::block::Header;
use rgb::bitcoin::constants::ChainHash;
use rgb::bitcoin::hashes::{sha256d, Hash as _, HashEngine as _};
use rgb::bitcoin::{BlockHash, TxMerkleNode, Txid};
use rgbcore::validation::{ResolveWitness, SpvProof, WitnessResolverError, WitnessStatus};
use rgbcore::vm::{WitnessOrd, WitnessPos};
use rgbcore::ChainNet;

use crate::indexers::ResolveSpvProof;

/// Error code Bitcoin Core returns for an unknown transaction.
const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;

/// Reported when the node cannot answer for lack of a transaction index.
const NO_TXINDEX: &str =
    "a synced transaction index (-txindex) is unavailable on the provided bitcoind node";

/// Wrapper of a Bitcoin Core RPC client, necessary to implement the foreign
/// `ResolveWitness` trait.
///
/// [`ResolveWitness::resolve_witness`] and [`ResolveSpvProof::resolve_spv_proof`] look transactions
/// up by id alone, which Core cannot do for non-wallet TXs without `-txindex`: both might fail on a
/// node running without this setting, and [`BitcoindClient::has_synced_txindex`] tells in advance
/// whether they can be used at all.
///
/// Verifying SPV proofs via [`ResolveWitness::get_block_header`] carries no such requirement and
/// keeps working on a pruned or light node, which is enough to validate a consignment whose
/// witnesses all come with a proof, hence [`ResolveWitness::check_chain_net`] accepts it.
/// Producing proofs does need the block, so it is limited to blocks the node still stores.
pub struct BitcoindClient {
    pub inner: Client,
    /// Cache of a positive answer from [`BitcoindClient::has_synced_txindex`].
    ///
    /// Only the positive one is cached: a node which has a synced transaction index keeps
    /// it synced, while a node still building one is expected to become usable later.
    txindex_synced: AtomicBool,
}

fn resolver_issue(txid: Option<Txid>, err: impl ToString) -> WitnessResolverError {
    WitnessResolverError::ResolverIssue(txid, err.to_string())
}

/// Whether the error is Bitcoin Core reporting that it has no such transaction.
///
/// Core answers this both for a transaction which does not exist and for one it cannot
/// look up for lack of a transaction index, so the two have to be told apart via
/// [`BitcoindClient::has_synced_txindex`].
fn is_no_such_tx(err: &RpcError) -> bool {
    matches!(err, RpcError::JsonRpc(jsonrpc::Error::Rpc(e)) if e.code == RPC_INVALID_ADDRESS_OR_KEY)
}

/// Sibling hashes along the merkle path of the transaction at `pos`, bottom-up, in the
/// format expected by [`SpvProof::merkle`].
///
/// A layer holding an odd number of nodes duplicates its last one, the way bitcoin builds
/// the block merkle tree.
fn merkle_branch(txids: &[Txid], pos: usize) -> Vec<TxMerkleNode> {
    let mut branch = vec![];
    let mut pos = pos;
    let mut layer = txids
        .iter()
        .map(|txid| txid.to_raw_hash())
        .collect::<Vec<_>>();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(*layer.last().expect("layer is not empty"));
        }
        branch.push(TxMerkleNode::from_raw_hash(layer[pos ^ 1]));
        layer = layer
            .chunks(2)
            .map(|pair| {
                let mut engine = sha256d::Hash::engine();
                engine.input(&pair[0].to_byte_array());
                engine.input(&pair[1].to_byte_array());
                sha256d::Hash::from_engine(engine)
            })
            .collect();
        pos /= 2;
    }
    branch
}

impl BitcoindClient {
    /// Wrap the given Bitcoin Core RPC client.
    pub fn new(inner: Client) -> Self {
        Self {
            inner,
            txindex_synced: AtomicBool::new(false),
        }
    }

    /// Whether the node maintains a transaction index and has finished building it.
    ///
    /// Without it Core cannot look a transaction up by id alone, and reports that the same
    /// way as for a transaction which does not exist. [`ResolveWitness::resolve_witness`]
    /// and [`ResolveSpvProof::resolve_spv_proof`] therefore error out on such a node,
    /// which this method allows telling apart from a genuinely unknown transaction ahead
    /// of asking.
    pub fn has_synced_txindex(&self) -> Result<bool, WitnessResolverError> {
        if self.txindex_synced.load(Ordering::Relaxed) {
            return Ok(true);
        }
        let info = self
            .inner
            .get_index_info()
            .map_err(|e| resolver_issue(None, e))?;
        let synced = matches!(info.txindex, Some(status) if status.synced);
        if synced {
            self.txindex_synced.store(true, Ordering::Relaxed);
        }
        Ok(synced)
    }

    /// Height of the block with the given hash, or `None` if it is not in the best chain.
    fn active_chain_height(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<u32>, WitnessResolverError> {
        let info = self
            .inner
            .get_block_header_info(block_hash)
            .map_err(|e| resolver_issue(None, e))?;
        // Core reports -1 confirmations for a block which is not in the best chain
        if info.confirmations < 0 {
            return Ok(None);
        }
        u32::try_from(info.height)
            .map(Some)
            .map_err(|_| WitnessResolverError::InvalidResolverData)
    }
}

impl ResolveWitness for BitcoindClient {
    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        // check the node is for the correct network
        let block_hash = self
            .inner
            .get_block_hash(0)
            .map_err(|e| resolver_issue(None, e))?;
        if chain_net.chain_hash() != ChainHash::from_genesis_block_hash(block_hash) {
            return Err(WitnessResolverError::WrongChainNet);
        }
        Ok(())
    }

    fn resolve_witness(&self, txid: Txid) -> Result<WitnessStatus, WitnessResolverError> {
        let info = match self.inner.get_raw_transaction_info(&txid, None) {
            Ok(info) => info,
            // Reporting a witness as unresolved archives it, so this must be answered only
            // when the TX is provably absent from the chain. A node with no transaction
            // index cannot tell that apart from one it just cannot look up, hence the
            // check: `check_chain_net` rejects such a node, but it is not on every path
            // reaching this method.
            Err(e) if is_no_such_tx(&e) => {
                return if self.has_synced_txindex()? {
                    Ok(WitnessStatus::Unresolved)
                } else {
                    Err(resolver_issue(Some(txid), NO_TXINDEX))
                };
            }
            Err(e) => return Err(resolver_issue(Some(txid), e)),
        };
        let tx = info
            .transaction()
            .map_err(|_| WitnessResolverError::InvalidResolverData)?;
        // no block hash means the TX is still in the mempool
        let Some(block_hash) = info.blockhash else {
            return Ok(WitnessStatus::Resolved(tx, WitnessOrd::Tentative));
        };
        // the TX is known, but the block confirming it has been reorged out
        let Some(height) = self.active_chain_height(&block_hash)? else {
            return Ok(WitnessStatus::Resolved(tx, WitnessOrd::Tentative));
        };
        let height = NonZeroU32::new(height).ok_or(WitnessResolverError::InvalidResolverData)?;
        let block_time = info
            .blocktime
            .ok_or(WitnessResolverError::InvalidResolverData)?;
        let pos = WitnessPos::bitcoin(height, block_time as i64)
            .ok_or(WitnessResolverError::InvalidResolverData)?;
        Ok(WitnessStatus::Resolved(tx, WitnessOrd::Mined(pos)))
    }

    fn get_block_header(&self, height: NonZeroU32) -> Result<Header, WitnessResolverError> {
        // Resolve by height: Core keeps stale blocks in its index and would happily serve a
        // header for one, so only the height-keyed lookup establishes the best chain.
        let block_hash = self
            .inner
            .get_block_hash(height.get() as u64)
            .map_err(|e| resolver_issue(None, e))?;
        self.inner
            .get_block_header(&block_hash)
            .map_err(|e| resolver_issue(None, e))
    }
}

impl ResolveSpvProof for BitcoindClient {
    fn resolve_spv_proof(&self, txid: Txid) -> Result<SpvProof, WitnessResolverError> {
        let info = match self.inner.get_raw_transaction_info(&txid, None) {
            Ok(info) => info,
            Err(e) if is_no_such_tx(&e) => {
                return if self.has_synced_txindex()? {
                    Err(resolver_issue(Some(txid), "TX is unknown or not mined"))
                } else {
                    Err(resolver_issue(Some(txid), NO_TXINDEX))
                };
            }
            Err(e) => return Err(resolver_issue(Some(txid), e)),
        };
        let Some(block_hash) = info.blockhash else {
            return Err(resolver_issue(Some(txid), "TX is unknown or not mined"));
        };
        // Core has no way to serve the merkle branch in the format of the proof, so it is
        // computed from the ordered list of the block TX ids
        let block = self
            .inner
            .get_block_info(&block_hash)
            .map_err(|e| resolver_issue(Some(txid), e))?;
        if block.confirmations < 0 {
            return Err(resolver_issue(Some(txid), "TX is mined in a stale block"));
        }
        let block_height = u32::try_from(block.height)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(WitnessResolverError::InvalidResolverData)?;
        let index = block
            .tx
            .iter()
            .position(|id| *id == txid)
            .ok_or(WitnessResolverError::InvalidResolverData)?;
        let merkle = Confined::try_from(merkle_branch(&block.tx, index))
            .map_err(|_| WitnessResolverError::InvalidResolverData)?;
        let pos = u32::try_from(index).map_err(|_| WitnessResolverError::InvalidResolverData)?;
        Ok(SpvProof {
            block_height,
            pos,
            merkle,
        })
    }
}
