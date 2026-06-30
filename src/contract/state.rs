// RGB ops library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2025-2026 RGB-Tools developers.
//
// Portions of this file are derived from other file(s) of the original
// project, some of which may since have been renamed, moved, or deleted:
//   Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Everything else in this file, including all modifications made to
// the derived portions, is copyright RGB-Tools developers as stated
// above.
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

//! Contract state held in memory, and the read interface it shares with the
//! persistent reader.
//!
//! [`UnfilteredContractState`] accumulates the raw state data of a contract as
//! operations are added to it, without interpreting or validating them. A
//! [`FilteredContractState`] wraps it together with the witness ords and
//! invalidated operations which decide what of it is visible, and answers
//! [`ContractStateAccess`]/[`ContractStateRead`] queries over the result.
//!
//! This is the store-less sibling of
//! [`ContractStateReader`](crate::persistence::ContractStateReader), which
//! answers the same traits by reading persisted rows. The two deliberately
//! coexist - one is fed operations in memory, the other reads a store - and
//! share the global-state ordering and filtering rules ([`global_ord`],
//! [`GlobalStateIter`]) so that their answers agree.

use std::borrow::Borrow;
use std::collections::{BTreeSet, HashMap};
use std::convert::Infallible;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::rc::Rc;

use amplify::confinement::{LargeOrdMap, LargeOrdSet, TinyOrdMap};
use amplify::num::u24;
use rgb::bitcoin::{OutPoint as Outpoint, Txid};
use rgb::vm::{
    ContractStateAccess, ContractStateEvolve, GlobalOrd, GlobalStateEntry, GlobalsIter, OrdOpRef,
    UnknownGlobalStateType, WitnessOrd,
};
use rgb::{
    Assign, AssignmentType, Assignments, AssignmentsRef, BundleId, ContractId, ExposedSeal,
    ExposedState, FungibleState, GlobalStateType, OpId, Operation, RevealedData, RevealedValue,
    Schema, SchemaId, TypedAssigns, VoidState,
};

use crate::contract::{GlobalOut, KnownState, OpWitness, OutputAssignment};
#[cfg(feature = "legacy")]
use crate::LIB_NAME_RGB_STORAGE;

/// Failure of a global-state read through [`ContractStateRead::global_all`].
#[derive(Copy, Clone, Debug, Display, Error)]
#[display(inner)]
pub enum GlobalStateReadError<E: Error> {
    /// the requested type is not part of the contract's schema.
    UnknownType(UnknownGlobalStateType),

    /// the state could not be read.
    Read(E),
}

/// Read access to a single contract's computed state.
pub trait ContractStateRead {
    type Error: Error;

    fn contract_id(&self) -> ContractId;
    fn schema_id(&self) -> SchemaId;
    fn witness_ord(&self, witness_id: Txid) -> Result<Option<WitnessOrd>, Self::Error>;
    fn global_all(
        &self,
        ty: GlobalStateType,
    ) -> Result<
        impl GlobalsIter<Item = impl Borrow<GlobalStateEntry>>,
        GlobalStateReadError<Self::Error>,
    >;
    fn rights_all(
        &self,
        type_id: Option<AssignmentType>,
    ) -> impl Iterator<Item = Result<OutputAssignment<VoidState>, Self::Error>> + '_;
    fn fungible_all(
        &self,
        type_id: Option<AssignmentType>,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedValue>, Self::Error>> + '_;
    fn data_all(
        &self,
        type_id: Option<AssignmentType>,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedData>, Self::Error>> + '_;
}

// ----- shared global-state helpers --------------------------------------------

/// Computes the consensus [`GlobalOrd`] of a global-state entry, applying the
/// same witness-validity rule as owned-state allocations: an entry whose witness
/// is unknown or archived is filtered out (`None`). Shared by
/// [`FilteredContractState`] and the persistent
/// [`ContractStateReader`](crate::persistence::ContractStateReader), so the two
/// agree on ordering and filtering.
pub(crate) fn global_ord(out: &GlobalOut, witness_ord: Option<WitnessOrd>) -> Option<GlobalOrd> {
    match out.op_witness {
        OpWitness::Genesis => Some(GlobalOrd::genesis(out.index)),
        OpWitness::Transition(_, ty) => {
            let ord = witness_ord?;
            if ord == WitnessOrd::Archived {
                return None;
            }
            Some(GlobalOrd::transition(out.opid, out.index, ty, out.nonce, ord))
        }
    }
}

/// The entries of a single global-state type, ordered by depth.
///
/// *Depth* is position in the contract's consensus ordering, counted from the
/// most recent entry: depth 0 is the value a contract reads as current, and
/// each step down is one entry further back, with genesis always deepest.
/// It is what the AluVM addresses through [`GlobalsIter::at_depth`] - the `LdC`
/// opcode loads the entry at the depth held in a register - and iterating this
/// type walks the same order, depth 0 first.
///
/// It is *not* depth in the chain. The order is [`GlobalOrd`]'s, which ranks a
/// witness by its [`WitnessOrd`] before anything else, and an unmined witness
/// outranks a mined one - so depth 0 may well be an entry whose witness is
/// still only tentative, sitting above entries confirmed long ago. Among mined
/// witnesses the more recent position is the shallower one; entries sharing a
/// witness are separated by transition type, nonce, operation id and index, in
/// that order.
///
/// The range of depths is capped by the schema's per-type limit: entries past
/// it are dropped, and asking for a deeper one yields `None`. Archived entries
/// are not here at all, having been filtered out by [`global_ord`] before the
/// ordering is applied.
///
/// Shared by [`FilteredContractState`] and the persistent
/// [`ContractStateReader`](crate::persistence::ContractStateReader), so both
/// answer the same depth with the same entry.
pub(crate) struct GlobalStateIter {
    values: Vec<Rc<GlobalStateEntry>>,
    idx: usize,
}

impl GlobalStateIter {
    pub(crate) fn new(
        entries: impl IntoIterator<Item = (GlobalOrd, RevealedData)>,
        limit: u32,
    ) -> Self {
        let mut values: Vec<Rc<GlobalStateEntry>> = entries
            .into_iter()
            .map(|(ord, data)| Rc::new(GlobalStateEntry::new(ord, data)))
            .collect();
        // ascending by GlobalOrd, then reversed, so index 0 is the most recent
        // entry and index n the n-th step back - the depth the VM asks for
        values.sort();
        values.reverse();
        // the limit truncates the deep end: it bounds how far back a contract
        // may look, so it has to be applied to the ordered entries and not to
        // whatever order they arrived in
        values.truncate(limit as usize);
        Self { values, idx: 0 }
    }
}

impl Iterator for GlobalStateIter {
    type Item = Rc<GlobalStateEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.values.get(self.idx)?.clone();
        self.idx += 1;
        Some(entry)
    }

    // O(1) over the items left to yield; the default would walk them one by one
    fn count(self) -> usize { self.values.len() - self.idx }
}

impl GlobalsIter for GlobalStateIter {
    /// The entry `depth` steps back from the most recent one; `None` past the
    /// end, which the schema's per-type limit sets. Independent of how far
    /// iteration has advanced.
    fn at_depth(&self, depth: usize) -> Option<Self::Item> { self.values.get(depth).cloned() }
}

// ----- unfiltered state ------------------------------------------------------

/// Every known entry of a single global state type, with the schema's limit on
/// how many of them are visible at a time.
#[derive(Getters, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "legacy", derive(StrictType, StrictDumb, StrictDecode))]
#[cfg_attr(feature = "legacy", strict_type(lib = LIB_NAME_RGB_STORAGE))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct UnfilteredGlobalState {
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    known: LargeOrdMap<GlobalOut, RevealedData>,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::small_int"))]
    limit: u24,
}

impl UnfilteredGlobalState {
    pub fn new(limit: u24) -> Self {
        UnfilteredGlobalState {
            known: empty!(),
            limit,
        }
    }
}

/// Raw contract state, accumulated from the operations of a contract history as
/// they are extracted from consignments over time.
///
/// It records what consensus ordering is later computed *from* - each global
/// entry is filed under a [`GlobalOut`], which carries the operation, its
/// witness and its nonce - but it does not apply that ordering itself. Its
/// global map is keyed by `GlobalOut`, whose ordering starts at the entry index
/// and has nothing to do with [`GlobalOrd`]'s, so the order entries sit in here
/// is not the order a contract sees them in. Reading them out in map order, or
/// taking some prefix of it, gives an arbitrary selection rather than the most
/// recent state.
///
/// It also neither interprets nor validates the state against the schema - it
/// only takes the schema to know which global types to keep a map for - and it
/// holds no notion of which of its entries are currently visible: everything
/// ever added stays. Consensus ordering and filtering by witness validity are
/// both applied on top, by [`FilteredContractState`] and its persistent
/// counterpart, through this module's `global_ord` and `GlobalStateIter`. No
/// query answered directly off this type may be treated as contract state.
#[derive(Getters, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "legacy", derive(StrictType, StrictDumb, StrictDecode))]
#[cfg_attr(feature = "legacy", strict_type(lib = LIB_NAME_RGB_STORAGE))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct UnfilteredContractState {
    #[getter(as_copy)]
    schema_id: SchemaId,
    #[getter(as_copy)]
    contract_id: ContractId,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    global: TinyOrdMap<GlobalStateType, UnfilteredGlobalState>,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    rights: LargeOrdSet<OutputAssignment<VoidState>>,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    fungibles: LargeOrdSet<OutputAssignment<RevealedValue>>,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    data: LargeOrdSet<OutputAssignment<RevealedData>>,
}

impl UnfilteredContractState {
    pub fn new(schema: &Schema, contract_id: ContractId) -> Self {
        let global = TinyOrdMap::from_iter_checked(schema.global_types.iter().map(|(ty, glob)| {
            (*ty, UnfilteredGlobalState::new(glob.global_state_schema.max_items))
        }));
        UnfilteredContractState {
            schema_id: schema.schema_id(),
            contract_id,
            global,
            rights: empty!(),
            fungibles: empty!(),
            data: empty!(),
        }
    }

    /// # Panics
    ///
    /// If the operation violates RGB consensus rules and wasn't checked against
    /// the schema before being added to the history.
    pub(crate) fn add_operation(&mut self, op: OrdOpRef) {
        let opid = op.id();

        for (ty, state) in op.globals() {
            let map = self
                .global
                .get_mut(ty)
                .expect("global map must be initialized from the schema");
            for (idx, s) in state.iter().enumerate() {
                let out = GlobalOut {
                    index: idx as u16,
                    op_witness: OpWitness::from(op),
                    nonce: op.nonce(),
                    opid,
                };
                map.known
                    .insert(out, s.clone())
                    .expect("contract global state exceeded 2^32 items, which is unrealistic");
            }
        }

        let bundle_id = op.bundle_id();
        let witness_id = op.witness_id();
        match op.assignments() {
            AssignmentsRef::Genesis(assignments) => {
                self.add_assignments(bundle_id, witness_id, opid, assignments)
            }
            AssignmentsRef::Graph(assignments) => {
                self.add_assignments(bundle_id, witness_id, opid, assignments)
            }
        }
    }

    fn add_assignments<Seal: ExposedSeal>(
        &mut self,
        bundle_id: Option<BundleId>,
        witness_id: Option<Txid>,
        opid: OpId,
        assignments: &Assignments<Seal>,
    ) {
        fn process<State: ExposedState + KnownState, Seal: ExposedSeal>(
            contract_state: &mut LargeOrdSet<OutputAssignment<State>>,
            assignments: &[Assign<State, Seal>],
            bundle_id: Option<BundleId>,
            opid: OpId,
            ty: AssignmentType,
            witness_id: Option<Txid>,
        ) {
            for (no, seal, state) in assignments
                .iter()
                .enumerate()
                .filter_map(|(n, a)| a.to_revealed().map(|(seal, state)| (n, seal, state)))
            {
                let assigned_state = match witness_id {
                    Some(witness_id) => OutputAssignment::with_witness(
                        seal, witness_id, state, bundle_id, opid, ty, no as u16,
                    ),
                    None => OutputAssignment::with_no_witness(
                        seal, state, bundle_id, opid, ty, no as u16,
                    ),
                };
                contract_state
                    .push(assigned_state)
                    .expect("contract state exceeded 2^32 items, which is unrealistic");
            }
        }

        for (ty, assignments) in assignments.iter() {
            match assignments {
                TypedAssigns::Declarative(assignments) => {
                    process(&mut self.rights, assignments, bundle_id, opid, *ty, witness_id)
                }
                TypedAssigns::Fungible(assignments) => {
                    process(&mut self.fungibles, assignments, bundle_id, opid, *ty, witness_id)
                }
                TypedAssigns::Structured(assignments) => {
                    process(&mut self.data, assignments, bundle_id, opid, *ty, witness_id)
                }
            }
        }
    }
}

// ----- filtered state --------------------------------------------------------

/// Contract state as it is actually visible: an [`UnfilteredContractState`]
/// read through the witness ords and the set of invalidated operations which
/// decide what of it counts.
///
/// Used *during validation*, where it accumulates operations via
/// [`ContractStateEvolve`] with no backing store and answers the RGB VM's
/// [`ContractStateAccess`] queries, and to read the state of a consignment
/// which has not been consumed into a store yet.
///
/// The generic parameter lets the unfiltered state be either owned or borrowed.
pub struct FilteredContractState<M: Borrow<UnfilteredContractState> = UnfilteredContractState> {
    filter: HashMap<Txid, WitnessOrd>,
    invalid_ops: BTreeSet<OpId>,
    unfiltered: M,
}

impl<M: Borrow<UnfilteredContractState>> FilteredContractState<M> {
    pub(crate) fn new(
        filter: HashMap<Txid, WitnessOrd>,
        invalid_ops: BTreeSet<OpId>,
        unfiltered: M,
    ) -> Self {
        Self {
            filter,
            invalid_ops,
            unfiltered,
        }
    }
}

impl<M: Borrow<UnfilteredContractState>> Debug for FilteredContractState<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("FilteredContractState { .. }")
    }
}

impl<M: Borrow<UnfilteredContractState>> ContractStateAccess for FilteredContractState<M> {
    fn global(
        &self,
        ty: GlobalStateType,
    ) -> Result<impl GlobalsIter<Item = impl Borrow<GlobalStateEntry>>, UnknownGlobalStateType>
    {
        // this state is held in memory, so the only way the read below fails is
        // the requested type being unknown
        ContractStateRead::global_all(self, ty).map_err(|err| match err {
            GlobalStateReadError::UnknownType(err) => err,
            GlobalStateReadError::Read(never) => match never {},
        })
    }

    fn rights(&self, outpoint: Outpoint, ty: AssignmentType) -> u32 {
        self.unfiltered
            .borrow()
            .rights
            .iter()
            .filter(|assignment| {
                assignment.seal.to_outpoint() == outpoint && assignment.opout.ty == ty
            })
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_op(&self.invalid_ops))
            .count() as u32
    }

    fn fungible(
        &self,
        outpoint: Outpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = FungibleState> {
        self.unfiltered
            .borrow()
            .fungibles
            .iter()
            .filter(move |assignment| {
                assignment.seal.to_outpoint() == outpoint && assignment.opout.ty == ty
            })
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_op(&self.invalid_ops))
            .map(|assignment| assignment.state.into())
    }

    fn data(
        &self,
        outpoint: Outpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = impl Borrow<RevealedData>> {
        self.unfiltered
            .borrow()
            .data
            .iter()
            .filter(move |assignment| {
                assignment.seal.to_outpoint() == outpoint && assignment.opout.ty == ty
            })
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_op(&self.invalid_ops))
            .map(|assignment| &assignment.state)
    }
}

impl ContractStateEvolve for FilteredContractState<UnfilteredContractState> {
    type Context<'ctx> = (&'ctx Schema, ContractId);
    type Error = Infallible;

    fn init(context: Self::Context<'_>) -> Self {
        Self {
            filter: empty!(),
            invalid_ops: empty!(),
            unfiltered: UnfilteredContractState::new(context.0, context.1),
        }
    }

    fn evolve_state(&mut self, op: OrdOpRef) -> Result<(), Self::Error> {
        if let OrdOpRef::Transition(_, witness_id, ord, _) = op {
            // NB: We do not check the existence of the witness since we have a
            // newer version anyway and even if it is known we have to replace it
            self.filter.insert(witness_id, ord);
        }
        self.unfiltered.add_operation(op);
        Ok(())
    }
}

impl<M: Borrow<UnfilteredContractState>> ContractStateRead for FilteredContractState<M> {
    type Error = Infallible;

    fn global_all(
        &self,
        ty: GlobalStateType,
    ) -> Result<
        impl GlobalsIter<Item = impl Borrow<GlobalStateEntry>>,
        GlobalStateReadError<Self::Error>,
    > {
        let state = self
            .unfiltered
            .borrow()
            .global
            .get(&ty)
            .ok_or(GlobalStateReadError::UnknownType(UnknownGlobalStateType(ty)))?;
        let items = state
            .known
            .as_unconfined()
            .iter()
            .rev()
            .filter_map(|(out, data)| {
                let ord = out
                    .witness_id()
                    .and_then(|id| self.filter.get(&id).copied());
                Some((global_ord(out, ord)?, data.to_owned()))
            });
        Ok(GlobalStateIter::new(items, state.limit.to_u32()))
    }

    #[inline]
    fn contract_id(&self) -> ContractId { self.unfiltered.borrow().contract_id }

    #[inline]
    fn schema_id(&self) -> SchemaId { self.unfiltered.borrow().schema_id }

    #[inline]
    fn witness_ord(&self, witness_id: Txid) -> Result<Option<WitnessOrd>, Self::Error> {
        Ok(self.filter.get(&witness_id).copied())
    }

    #[inline]
    fn rights_all(
        &self,
        type_id: Option<AssignmentType>,
    ) -> impl Iterator<Item = Result<OutputAssignment<VoidState>, Self::Error>> + '_ {
        self.unfiltered
            .borrow()
            .rights
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_op(&self.invalid_ops))
            .filter(move |assignment| type_id.is_none_or(|ty| assignment.opout.ty == ty))
            .cloned()
            .map(Ok)
    }

    #[inline]
    fn fungible_all(
        &self,
        type_id: Option<AssignmentType>,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedValue>, Self::Error>> + '_ {
        self.unfiltered
            .borrow()
            .fungibles
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_op(&self.invalid_ops))
            .filter(move |assignment| type_id.is_none_or(|ty| assignment.opout.ty == ty))
            .cloned()
            .map(Ok)
    }

    #[inline]
    fn data_all(
        &self,
        type_id: Option<AssignmentType>,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedData>, Self::Error>> + '_ {
        self.unfiltered
            .borrow()
            .data
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_op(&self.invalid_ops))
            .filter(move |assignment| type_id.is_none_or(|ty| assignment.opout.ty == ty))
            .cloned()
            .map(Ok)
    }
}
