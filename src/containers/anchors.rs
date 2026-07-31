// RGB ops library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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

use std::cmp::Ordering;

use amplify::ByteArray;
use rgb::bitcoin::{Transaction as Tx, Txid};
use rgb::commit_verify::{mpc, CommitEncode, CommitEngine};
use rgb::dbc::Anchor;
pub use rgb::validation::SpvProof;
use rgb::validation::{DbcProof, EAnchor};
use rgb::{BundleId, DiscloseHash, TransitionBundle};
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};
use strict_encoding::StrictDumb;

use crate::{MergeReveal, MergeRevealError, LIB_NAME_RGB_OPS};

/// Error merging two [`SealWitness`]es.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SealWitnessMergeError {
    /// Error merging two MPC proofs, which are unrelated.
    #[display(inner)]
    #[from]
    MpcMismatch(mpc::MergeError),

    /// Error merging two witness proofs, which are unrelated.
    #[display(inner)]
    #[from]
    WitnessMergeError(MergeRevealError),

    /// seal witnesses can't be merged since they have different DBC proofs.
    DbcMismatch,

    /// seal witnesses can't be merged since they have different SPV proofs.
    SpvMismatch,
}

/// Witness of a bundle: the transaction closing the seals, together with the
/// commitment proofs.
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SealWitness {
    pub tx: Tx,
    pub merkle_block: mpc::MerkleBlock,
    pub dbc_proof: DbcProof,
    pub spv_proof: Option<SpvProof>,
}

impl SealWitness {
    pub fn new(
        tx: Tx,
        merkle_block: mpc::MerkleBlock,
        dbc_proof: DbcProof,
        spv_proof: Option<SpvProof>,
    ) -> Self {
        SealWitness {
            tx,
            merkle_block,
            dbc_proof,
            spv_proof,
        }
    }

    pub fn witness_id(&self) -> Txid { self.tx.compute_txid() }

    /// Merges two [`SealWitness`]es keeping revealed data.
    pub fn merge_reveal(&mut self, other: &Self) -> Result<(), SealWitnessMergeError> {
        if self.dbc_proof != other.dbc_proof {
            return Err(SealWitnessMergeError::DbcMismatch);
        }
        self.tx.merge_reveal(&other.tx)?;
        self.merkle_block.merge_reveal(&other.merkle_block)?;
        match (&self.spv_proof, &other.spv_proof) {
            (Some(spv1), Some(spv2)) if spv1 != spv2 => {
                return Err(SealWitnessMergeError::SpvMismatch);
            }
            (None, Some(_)) => self.spv_proof = other.spv_proof.clone(),
            _ => {}
        }
        Ok(())
    }

    pub fn known_bundle_ids(&self) -> impl Iterator<Item = BundleId> {
        let map = self.merkle_block.to_known_message_map().release();
        map.into_values()
            .map(|msg| BundleId::from_byte_array(msg.to_byte_array()))
    }
}

impl MergeReveal for Tx {
    fn merge_reveal(&mut self, other: &Self) -> Result<(), MergeRevealError> {
        if self == other {
            return Ok(());
        }
        let txid = self.compute_txid();
        if txid != other.compute_txid() {
            return Err(MergeRevealError::TxidMismatch(txid, other.compute_txid()));
        }
        // Replace each input with the one from `other` if it carries more
        // witness or sig_script data
        for (input1, input2) in self.input.iter_mut().zip(other.input.iter()) {
            let input1_witness_len: usize = input1.witness.iter().map(|w| w.len()).sum();
            let input2_witness_len: usize = input2.witness.iter().map(|w| w.len()).sum();
            match input1_witness_len.cmp(&input2_witness_len) {
                Ordering::Less => *input1 = input2.clone(),
                Ordering::Equal => {
                    if input2.script_sig.len() > input1.script_sig.len() {
                        *input1 = input2.clone();
                    }
                }
                Ordering::Greater => {}
            }
        }
        Ok(())
    }
}

/// Bundle of state transitions together with their witness data.
///
/// The witness is always a full transaction, as required by the V1
/// consignment wire format; field order matches it, so strict encoding is
/// derived. The legacy V0 bundle, whose witness may be an unresolved txid, is
/// [`crate::containers::legacy::WitnessBundleV0`].
#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct WitnessBundle {
    pub tx: Tx,
    pub spv_proof: Option<SpvProof>,
    pub anchor: Anchor<DbcProof>,
    pub bundle: TransitionBundle,
}

impl CommitEncode for WitnessBundle {
    type CommitmentId = DiscloseHash;

    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_serialized(&self); }
}

impl PartialEq for WitnessBundle {
    fn eq(&self, other: &Self) -> bool { self.witness_id() == other.witness_id() }
}

impl Ord for WitnessBundle {
    fn cmp(&self, other: &Self) -> Ordering { self.witness_id().cmp(&other.witness_id()) }
}

impl PartialOrd for WitnessBundle {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl WitnessBundle {
    #[inline]
    pub fn with(tx: Tx, anchor: Anchor<DbcProof>, bundle: TransitionBundle) -> Self {
        Self {
            tx,
            anchor,
            bundle,
            spv_proof: None,
        }
    }

    pub fn witness_id(&self) -> Txid { self.tx.compute_txid() }

    pub fn bundle(&self) -> &TransitionBundle { &self.bundle }

    pub fn bundle_mut(&mut self) -> &mut TransitionBundle { &mut self.bundle }

    pub fn eanchor(&self) -> EAnchor {
        EAnchor::new(self.anchor.mpc_proof.clone(), self.anchor.dbc_proof.clone())
    }
}
