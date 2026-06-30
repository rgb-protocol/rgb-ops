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

use std::borrow::Borrow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;

use invoice::{Allocation, Amount};
use rgb::bitcoin::OutPoint as Outpoint;
use rgb::{
    AssignmentType, ContractId, GlobalStateType, OpId, OutputSeal, RevealedData, RevealedValue,
    Schema, Txid, VoidState,
};
use strict_encoding::{FieldName, StrictDecode, StrictDumb, StrictEncode};
use strict_types::StrictVal;

use crate::contract::{
    AssignmentsFilter, ContractStateRead, KnownState, OutputAssignment, WitnessInfo,
};
use crate::info::ContractInfo;
use crate::validation::SchemaRules;
use crate::LIB_NAME_RGB_OPS;

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ContractError {
    /// field name {0} is unknown to the contract schema
    FieldNameUnknown(FieldName),

    /// unable to read the contract state: {0}
    StateRead(String),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS, tags = custom)]
#[display(inner)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AllocatedState {
    #[from(())]
    #[from(VoidState)]
    #[display("~")]
    #[strict_type(tag = 0, dumb)]
    Void,

    #[from]
    #[from(Amount)]
    #[strict_type(tag = 1)]
    Amount(RevealedValue),

    #[from]
    #[from(Allocation)]
    #[strict_type(tag = 2)]
    Data(RevealedData),
}

impl KnownState for AllocatedState {
    const IS_FUNGIBLE: bool = false;
}

impl AllocatedState {
    fn unwrap_fungible(&self) -> Amount {
        match self {
            AllocatedState::Amount(revealed_value) => (*revealed_value).into(),
            _ => panic!("unwrapping non-fungible state"),
        }
    }
}

pub type OwnedAllocation = OutputAssignment<AllocatedState>;
pub type RightsAllocation = OutputAssignment<VoidState>;
pub type FungibleAllocation = OutputAssignment<Amount>;
pub type DataAllocation = OutputAssignment<RevealedData>;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(lowercase)]
pub enum OpDirection {
    Issued,
    Received,
    Sent,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub struct ContractOp {
    pub direction: OpDirection,
    pub ty: AssignmentType,
    pub opids: BTreeSet<OpId>,
    pub state: AllocatedState,
    pub to: BTreeSet<OutputSeal>,
    pub witness: Option<WitnessInfo>,
}

fn reduce_to_ty(allocations: impl IntoIterator<Item = OwnedAllocation>) -> AssignmentType {
    allocations
        .into_iter()
        .map(|a| a.opout.ty)
        .reduce(|ty1, ty2| {
            assert_eq!(ty1, ty2);
            ty1
        })
        .expect("empty list of allocations")
}

impl ContractOp {
    fn non_fungible_genesis(
        our_allocations: HashSet<OwnedAllocation>,
    ) -> impl ExactSizeIterator<Item = Self> {
        our_allocations.into_iter().map(|a| Self {
            direction: OpDirection::Issued,
            ty: a.opout.ty,
            opids: bset![a.opout.op],
            state: a.state,
            to: bset![a.seal],
            witness: None,
        })
    }

    fn non_fungible_sent(
        witness: WitnessInfo,
        ext_allocations: HashSet<OwnedAllocation>,
    ) -> impl ExactSizeIterator<Item = Self> {
        ext_allocations.into_iter().map(move |a| Self {
            direction: OpDirection::Sent,
            ty: a.opout.ty,
            opids: bset![a.opout.op],
            state: a.state,
            to: bset![a.seal],
            witness: Some(witness),
        })
    }

    fn non_fungible_received(
        witness: WitnessInfo,
        our_allocations: HashSet<OwnedAllocation>,
    ) -> impl ExactSizeIterator<Item = Self> {
        our_allocations.into_iter().map(move |a| Self {
            direction: OpDirection::Received,
            ty: a.opout.ty,
            opids: bset![a.opout.op],
            state: a.state,
            to: bset![a.seal],
            witness: Some(witness),
        })
    }

    fn fungible_genesis(our_allocations: HashSet<OwnedAllocation>) -> Self {
        let to = our_allocations.iter().map(|a| a.seal).collect();
        let opids = our_allocations.iter().map(|a| a.opout.op).collect();
        let issued: Amount = our_allocations
            .iter()
            .map(|a| a.state.unwrap_fungible())
            .sum();
        Self {
            direction: OpDirection::Issued,
            ty: reduce_to_ty(our_allocations),
            opids,
            state: AllocatedState::Amount(issued.into()),
            to,
            witness: None,
        }
    }

    fn fungible_sent(witness: WitnessInfo, ext_allocations: HashSet<OwnedAllocation>) -> Self {
        let opids = ext_allocations.iter().map(|a| a.opout.op).collect();
        let to = ext_allocations.iter().map(|a| a.seal).collect();
        let amount: Amount = ext_allocations
            .iter()
            .map(|a| a.state.unwrap_fungible())
            .sum();
        Self {
            direction: OpDirection::Sent,
            ty: reduce_to_ty(ext_allocations),
            opids,
            state: AllocatedState::Amount(amount.into()),
            to,
            witness: Some(witness),
        }
    }

    fn fungible_received(witness: WitnessInfo, our_allocations: HashSet<OwnedAllocation>) -> Self {
        let opids = our_allocations.iter().map(|a| a.opout.op).collect();
        let to = our_allocations.iter().map(|a| a.seal).collect();
        let amount: Amount = our_allocations
            .iter()
            .map(|a| a.state.unwrap_fungible())
            .sum();
        Self {
            direction: OpDirection::Received,
            ty: reduce_to_ty(our_allocations),
            opids,
            state: AllocatedState::Amount(amount.into()),
            to,
            witness: Some(witness),
        }
    }
}

/// Converts a state read failure into a [`ContractError`].
fn read_err<A: KnownState, E: Error>(
    res: Result<OutputAssignment<A>, E>,
) -> Result<OutputAssignment<A>, ContractError> {
    res.map_err(|e| ContractError::StateRead(e.to_string()))
}

/// Data of a contract.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ContractData<S: ContractStateRead> {
    pub state: S,
    /// The rules the contract was issued under: schema, type system and
    /// scripts.
    pub rules: SchemaRules,
    pub info: ContractInfo,
}

impl<S: ContractStateRead> ContractData<S> {
    pub fn contract_id(&self) -> ContractId { self.state.contract_id() }

    /// The schema the contract was issued under.
    #[inline]
    pub fn schema(&self) -> &Schema { self.rules.schema() }

    /// # Panics
    ///
    /// If data is corrupted.
    pub fn global(&self, name: impl Into<FieldName>) -> impl Iterator<Item = StrictVal> + '_ {
        self.global_raw(self.schema().global_type(name))
    }

    /// # Panics
    ///
    /// If data is corrupted.
    pub fn global_raw(&self, type_id: GlobalStateType) -> impl Iterator<Item = StrictVal> + '_ {
        let global_details = self
            .rules
            .schema()
            .global_types
            .get(&type_id)
            .expect("cannot find type ID in schema global types");
        self.state
            .global_all(type_id)
            .expect("cannot find type ID in global state")
            .map(|entry| {
                self.rules
                    .types()
                    .strict_deserialize_type(
                        global_details.global_state_schema.sem_id,
                        entry.borrow().data().as_slice(),
                    )
                    .expect("unvalidated contract data in store")
                    .unbox()
            })
    }

    fn extract_state<'c, A, U, E: Error + 'c>(
        &'c self,
        state: impl IntoIterator<Item = Result<OutputAssignment<A>, E>> + 'c,
        type_id: AssignmentType,
        filter: impl AssignmentsFilter + 'c,
    ) -> impl Iterator<Item = Result<OutputAssignment<U>, ContractError>> + 'c
    where
        A: Clone + KnownState + 'c,
        U: From<A> + KnownState + 'c,
    {
        self.extract_state_unfiltered::<A, U, E>(state, type_id)
            .filter(move |res| match res {
                Ok(outp) => filter.should_include(outp.seal, outp.witness),
                // read failures are never filtered out
                Err(_) => true,
            })
    }

    fn extract_state_unfiltered<'c, A, U, E: Error + 'c>(
        &'c self,
        state: impl IntoIterator<Item = Result<OutputAssignment<A>, E>> + 'c,
        type_id: AssignmentType,
    ) -> impl Iterator<Item = Result<OutputAssignment<U>, ContractError>> + 'c
    where
        A: Clone + KnownState + 'c,
        U: From<A> + KnownState + 'c,
    {
        state
            .into_iter()
            .map(read_err)
            .filter(move |res| match res {
                Ok(outp) => outp.opout.ty == type_id,
                // read failures are never filtered out
                Err(_) => true,
            })
            .map(|res| res.map(OutputAssignment::<A>::transmute))
    }

    pub fn rights<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> impl Iterator<Item = Result<RightsAllocation, ContractError>> + 'c {
        let type_id = self.schema().assignment_type(name);
        self.rights_raw(type_id, filter)
    }

    pub fn rights_raw<'c>(
        &'c self,
        type_id: AssignmentType,
        filter: impl AssignmentsFilter + 'c,
    ) -> impl Iterator<Item = Result<RightsAllocation, ContractError>> + 'c {
        self.extract_state(self.state.rights_all(Some(type_id)), type_id, filter)
    }

    pub fn fungible<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> impl Iterator<Item = Result<FungibleAllocation, ContractError>> + 'c {
        let type_id = self.schema().assignment_type(name);
        self.fungible_raw(type_id, filter)
    }

    pub fn fungible_raw<'c>(
        &'c self,
        type_id: AssignmentType,
        filter: impl AssignmentsFilter + 'c,
    ) -> impl Iterator<Item = Result<FungibleAllocation, ContractError>> + 'c {
        self.extract_state(self.state.fungible_all(Some(type_id)), type_id, filter)
    }

    pub fn data<'c>(
        &'c self,
        name: impl Into<FieldName>,
        filter: impl AssignmentsFilter + 'c,
    ) -> impl Iterator<Item = Result<DataAllocation, ContractError>> + 'c {
        let type_id = self.schema().assignment_type(name);
        self.data_raw(type_id, filter)
    }

    pub fn data_raw<'c>(
        &'c self,
        type_id: AssignmentType,
        filter: impl AssignmentsFilter + 'c,
    ) -> impl Iterator<Item = Result<DataAllocation, ContractError>> + 'c {
        self.extract_state(self.state.data_all(Some(type_id)), type_id, filter)
    }

    pub fn allocations<'c>(
        &'c self,
        filter: impl AssignmentsFilter + Copy + 'c,
    ) -> impl Iterator<Item = Result<OwnedAllocation, ContractError>> + 'c {
        fn f<'a, S, U, E: Error + 'a>(
            filter: impl AssignmentsFilter + 'a,
            state: impl IntoIterator<Item = Result<OutputAssignment<S>, E>> + 'a,
        ) -> impl Iterator<Item = Result<OutputAssignment<U>, ContractError>> + 'a
        where
            S: Clone + KnownState + 'a,
            U: From<S> + KnownState + 'a,
        {
            state
                .into_iter()
                .map(read_err)
                .filter(move |res| match res {
                    Ok(outp) => filter.should_include(outp.seal, outp.witness),
                    // read failures are never filtered out
                    Err(_) => true,
                })
                .map(|res| res.map(OutputAssignment::<S>::transmute))
        }

        f(filter, self.state.rights_all(None))
            .chain(f(filter, self.state.fungible_all(None)))
            .chain(f(filter, self.state.data_all(None)))
    }

    pub fn outpoint_allocations(
        &self,
        outpoint: Outpoint,
    ) -> impl Iterator<Item = Result<OwnedAllocation, ContractError>> + '_ {
        self.allocations(outpoint)
    }

    pub fn history(
        &self,
        filter_outpoints: impl AssignmentsFilter + Clone,
        filter_witnesses: impl AssignmentsFilter + Clone,
    ) -> Result<Vec<ContractOp>, ContractError> {
        Ok(self
            .history_fungible(filter_outpoints.clone(), filter_witnesses.clone())?
            .into_iter()
            .chain(self.history_rights(filter_outpoints.clone(), filter_witnesses.clone())?)
            .chain(self.history_data(filter_outpoints.clone(), filter_witnesses.clone())?)
            .collect())
    }

    fn operations<
        'c,
        T: KnownState + 'c,
        E: Error,
        I: Iterator<Item = Result<OutputAssignment<T>, E>> + 'c,
    >(
        &'c self,
        state: impl Fn(&'c S) -> I,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Result<Vec<ContractOp>, ContractError>
    where
        AllocatedState: From<T>,
    {
        // both maps are filled from one read of the state
        let mut allocations_our_outpoint = HashMap::<_, HashSet<_>>::new();
        let mut allocations_our_witness = HashMap::<_, HashSet<_>>::new();
        let allocations = state(&self.state)
            .map(read_err)
            .collect::<Result<Vec<_>, _>>()?;
        for allocation in allocations {
            let allocation = allocation.transmute::<AllocatedState>();
            // allocations which ever belonged to this wallet, kept by witness id
            if filter_outpoints.should_include(allocation.seal, allocation.witness) {
                allocations_our_outpoint
                    .entry(allocation.witness)
                    .or_default()
                    .insert(allocation.clone());
            }
            // allocations whose witness transaction belongs to this wallet
            if filter_witnesses.should_include(allocation.seal, allocation.witness) {
                let witness = allocation.witness.expect(
                    "all empty witnesses must be already filtered out by wallet.filter_witness()",
                );
                allocations_our_witness
                    .entry(witness)
                    .or_default()
                    .insert(allocation);
            }
        }

        // gather all witnesses from both sets
        let mut witness_ids = allocations_our_witness
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        witness_ids.extend(allocations_our_outpoint.keys().filter_map(|x| *x));

        // reconstruct contract history from the wallet perspective
        let mut ops = Vec::with_capacity(witness_ids.len() + 1);
        // add allocations with no witness to the beginning of the history
        if let Some(genesis_allocations) = allocations_our_outpoint.remove(&None) {
            if T::IS_FUNGIBLE {
                ops.push(ContractOp::fungible_genesis(genesis_allocations));
            } else {
                ops.extend(ContractOp::non_fungible_genesis(genesis_allocations));
            }
        }
        for witness_id in witness_ids {
            let our_outpoint = allocations_our_outpoint.remove(&Some(witness_id));
            let our_witness = allocations_our_witness.remove(&witness_id);
            let witness_info = self
                .witness_info(witness_id)
                .map_err(|e| ContractError::StateRead(e.to_string()))?
                .expect(
                    "witness id was returned from the contract state above, so it must be there",
                );
            match (our_outpoint, our_witness) {
                // we own both allocation and witness transaction: these allocations are changes and
                // outgoing payments. The difference between the change and the payments are whether
                // a specific allocation is listed in the first tuple pattern field.
                (Some(our_allocations), Some(all_allocations)) => {
                    // all_allocations - our_allocations = external payments
                    let ext_allocations = all_allocations
                        .difference(&our_allocations)
                        .cloned()
                        .collect::<HashSet<_>>();
                    // This was an extra state transition with no external payment
                    if ext_allocations.is_empty() {
                        continue;
                    }
                    if T::IS_FUNGIBLE {
                        ops.push(ContractOp::fungible_sent(witness_info, ext_allocations))
                    } else {
                        ops.extend(ContractOp::non_fungible_sent(witness_info, ext_allocations))
                    }
                }
                // the same as above, but the payment has no change
                (None, Some(ext_allocations)) => {
                    if T::IS_FUNGIBLE {
                        ops.push(ContractOp::fungible_sent(witness_info, ext_allocations))
                    } else {
                        ops.extend(ContractOp::non_fungible_sent(witness_info, ext_allocations))
                    }
                }
                // we own allocation but the witness transaction was made by other wallet:
                // this is an incoming payment to us.
                (Some(our_allocations), None) => {
                    if T::IS_FUNGIBLE {
                        ops.push(ContractOp::fungible_received(witness_info, our_allocations))
                    } else {
                        ops.extend(ContractOp::non_fungible_received(witness_info, our_allocations))
                    }
                }
                // these can't get into the `witness_ids` due to the used filters
                (None, None) => unreachable!("broken allocation filters"),
            };
        }

        Ok(ops)
    }

    pub fn history_fungible(
        &self,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Result<Vec<ContractOp>, ContractError> {
        self.operations(|state| state.fungible_all(None), filter_outpoints, filter_witnesses)
    }

    pub fn history_rights(
        &self,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Result<Vec<ContractOp>, ContractError> {
        self.operations(|state| state.rights_all(None), filter_outpoints, filter_witnesses)
    }

    pub fn history_data(
        &self,
        filter_outpoints: impl AssignmentsFilter,
        filter_witnesses: impl AssignmentsFilter,
    ) -> Result<Vec<ContractOp>, ContractError> {
        self.operations(|state| state.data_all(None), filter_outpoints, filter_witnesses)
    }

    /// Ordering information for a witness, `None` when the state does not know
    /// it.
    pub fn witness_info(
        &self,
        witness_id: Txid,
    ) -> Result<Option<WitnessInfo>, <S as ContractStateRead>::Error> {
        Ok(self.state.witness_ord(witness_id)?.map(|ord| WitnessInfo {
            id: witness_id,
            ord,
        }))
    }
}
