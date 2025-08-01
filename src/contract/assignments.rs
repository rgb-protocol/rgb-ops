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
use std::collections::{BTreeSet, HashMap};
use std::fmt::Debug;
use std::hash::Hash;

use invoice::Amount;
use rgb::vm::WitnessOrd;
use rgb::{
    AssignmentType, BundleId, ExposedSeal, OpId, Opout, OutputSeal, RevealedData, RevealedValue,
    Txid, VoidState,
};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::LIB_NAME_RGB_OPS;

/// Trait used by contract state. Unlike [`ExposedState`] it doesn't allow
/// concealment of the state, i.e. may contain incomplete data without blinding
/// factors, asset tags etc.
pub trait KnownState: Debug + StrictDumb + StrictEncode + StrictDecode + Eq + Clone + Hash {
    const IS_FUNGIBLE: bool;
}

impl KnownState for () {
    const IS_FUNGIBLE: bool = false;
}
impl KnownState for VoidState {
    const IS_FUNGIBLE: bool = false;
}
impl KnownState for Amount {
    const IS_FUNGIBLE: bool = true;
}
impl KnownState for RevealedValue {
    const IS_FUNGIBLE: bool = true;
}
impl KnownState for RevealedData {
    const IS_FUNGIBLE: bool = false;
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct WitnessInfo {
    pub id: Txid,
    pub ord: WitnessOrd,
}

#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Copy, Clone, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OutputAssignment<State: KnownState> {
    pub opout: Opout,
    pub seal: OutputSeal,
    pub state: State,
    pub witness: Option<Txid>,
    pub bundle_id: Option<BundleId>,
}

impl<State: KnownState> PartialEq for OutputAssignment<State> {
    fn eq(&self, other: &Self) -> bool {
        // We ignore difference in witness transactions, state and seal definitions here
        // in order to support updates from the ephemeral state of the lightning
        // channels. See <https://github.com/RGB-WG/rgb-std/issues/238#issuecomment-2283822128>
        // for the details.
        let res = self.opout == other.opout && self.seal == other.seal;
        #[cfg(debug_assertions)]
        if res {
            debug_assert_eq!(self.state, other.state);
        }
        res
    }
}

impl<State: KnownState> PartialOrd for OutputAssignment<State> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<State: KnownState> Ord for OutputAssignment<State> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        match self.opout.cmp(&other.opout) {
            Ordering::Equal => self.seal.cmp(&other.seal),
            ordering => ordering,
        }
    }
}

impl<State: KnownState> OutputAssignment<State> {
    /// # Panics
    ///
    /// If the processing is done on invalid stash data, the seal is
    /// witness-based and the anchor chain doesn't match the seal chain.
    pub fn with_witness<Seal: ExposedSeal>(
        seal: Seal,
        witness_id: Txid,
        state: State,
        bundle_id: Option<BundleId>,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal.to_output_seal_or_default(witness_id),
            state,
            bundle_id,
            witness: witness_id.into(),
        }
    }

    /// # Panics
    ///
    /// If the processing is done on invalid stash data, the seal is
    /// witness-based and the anchor chain doesn't match the seal chain.
    pub fn with_no_witness<Seal: ExposedSeal>(
        seal: Seal,
        state: State,
        bundle_id: Option<BundleId>,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal.to_output_seal().expect(
                "processing contract from unverified/invalid stash: seal must have txid \
                 information since it comes from genesis",
            ),
            state,
            bundle_id,
            witness: None,
        }
    }

    /// Transmutes output assignment from one form of state to another
    pub fn transmute<S: KnownState + From<State>>(self) -> OutputAssignment<S> {
        OutputAssignment {
            opout: self.opout,
            seal: self.seal,
            state: self.state.into(),
            bundle_id: self.bundle_id,
            witness: self.witness,
        }
    }

    pub fn check_witness(&self, filter: &HashMap<Txid, WitnessOrd>) -> bool {
        match self.witness {
            None => true,
            Some(witness_id) => {
                !matches!(filter.get(&witness_id), None | Some(WitnessOrd::Archived))
            }
        }
    }

    pub fn check_bundle(&self, invalid_bundles: &BTreeSet<BundleId>) -> bool {
        match self.bundle_id {
            Some(bundle_id) => !invalid_bundles.contains(&bundle_id),
            None => true,
        }
    }
}
