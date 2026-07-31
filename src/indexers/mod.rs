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

mod any;
#[cfg(feature = "esplora_blocking")]
pub mod esplora_blocking;
#[cfg(feature = "electrum_blocking")]
pub mod electrum_blocking;

#[cfg(feature = "mempool_blocking")]
pub mod mempool_blocking;

#[cfg(feature = "bitcoind_blocking")]
pub mod bitcoind_blocking;

pub use any::AnyResolver;
use rgb::bitcoin::Txid;
use rgb::validation::{ResolveWitness, SpvProof, WitnessResolverError};

/// Trait to retrieve the SPV inclusion proof of a mined TX.
///
/// This is the counterpart of the verification performed during validation via
/// [`ResolveWitness::get_block_header`]: it lets a wallet obtain, from its own indexer,
/// the proofs it then hands to its counterparties inside a consignment.
pub trait ResolveSpvProof {
    /// Return the [`SpvProof`] for the TX with the given `txid`.
    ///
    /// Fails if the TX is unknown to the indexer or is not mined yet.
    ///
    /// Returns `Err(NotSupported)` by default, so that an indexer whose backend cannot
    /// produce inclusion proofs opts out with an empty `impl` instead of a stub. Such an
    /// indexer stays fully usable: it simply never attaches proofs to the consignments it
    /// produces, and the ones it receives are verified by retrieving the witness TX.
    fn resolve_spv_proof(&self, _txid: Txid) -> Result<SpvProof, WitnessResolverError> {
        Err(WitnessResolverError::NotSupported)
    }
}

/// An indexer which [`AnyResolver`] can wrap.
///
/// Blanket-implemented; it exists only so that [`AnyResolver`] can hold a single boxed
/// value offering both capabilities. Producing SPV proofs is optional, see
/// [`ResolveSpvProof::resolve_spv_proof`].
pub trait Indexer: ResolveWitness + ResolveSpvProof {}

impl<T: ResolveWitness + ResolveSpvProof> Indexer for T {}
