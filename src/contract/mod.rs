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

mod assignments;
mod builder;
mod data;
mod filter;
mod merge_reveal;
mod schema;
pub(crate) mod resolver;

pub use assignments::{KnownState, OutputAssignment, WitnessInfo};
pub use builder::{BuilderError, ContractBuilder, TransitionBuilder};
pub use data::{
    AllocatedState, ContractData, ContractError, ContractOp, DataAllocation, FungibleAllocation,
    OpDirection, OwnedAllocation, RightsAllocation,
};
pub use filter::{AssignmentsFilter, FilterExclude, FilterIncludeAll};
pub use merge_reveal::{MergeReveal, MergeRevealError};
use rgb::vm::OrdOpRef;
use rgb::{OpId, TransitionType, Txid};
pub use schema::{IssuerWrapper, SchemaWrapper};

use crate::LIB_NAME_RGB_OPS;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum OpWitness {
    #[strict_type(dumb)]
    Genesis,
    Transition(Txid, TransitionType),
}

impl From<OrdOpRef<'_>> for OpWitness {
    fn from(aor: OrdOpRef) -> Self {
        match aor {
            OrdOpRef::Genesis(_) => OpWitness::Genesis,
            OrdOpRef::Transition(op, witness_id, ..) => {
                OpWitness::Transition(witness_id, op.transition_type)
            }
        }
    }
}

impl OpWitness {
    #[inline]
    pub fn witness_id(&self) -> Option<Txid> {
        match self {
            OpWitness::Genesis => None,
            OpWitness::Transition(witness_id, _) => Some(*witness_id),
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalOut {
    pub index: u16,
    pub op_witness: OpWitness,
    pub nonce: u64,
    pub opid: OpId,
}

impl GlobalOut {
    #[inline]
    pub fn witness_id(&self) -> Option<Txid> { self.op_witness.witness_id() }
}
