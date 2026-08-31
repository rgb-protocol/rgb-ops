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
use std::collections::{BTreeSet, HashMap};
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::rc::Rc;

use aluvm::library::{Lib, LibId};
use amplify::confinement::{
    self, LargeOrdMap, LargeOrdSet, MediumOrdSet, SmallOrdMap, SmallOrdSet, TinyOrdMap,
};
use amplify::num::u24;
use rgb::bitcoin::{OutPoint as Outpoint, Txid};
use rgb::vm::{
    ContractStateAccess, ContractStateEvolve, GlobalOrd, GlobalStateEntry, GlobalsIter, OrdOpRef,
    UnknownGlobalStateType, WitnessOrd,
};
use rgb::{
    Assign, AssignmentType, Assignments, AssignmentsRef, BundleId, ContractId, ExposedSeal,
    ExposedState, FungibleState, Genesis, GlobalStateType, GraphSeal, OpId, Operation, Opout,
    OutputSeal, RevealedData, RevealedValue, Schema, SchemaId, SecretSeal, Transition,
    TransitionBundle, TypedAssigns, VoidState,
};
use strict_encoding::{DefaultBasedStrictDumb, StrictDeserialize, StrictSerialize};
use strict_types::TypeSystem;

use super::{ContractStateRead, ContractStateWrite, IndexReadError, IndexWriteError};
use crate::containers::SealWitness;
use crate::contract::{GlobalOut, KnownState, OpWitness, OutputAssignment};
use crate::LIB_NAME_RGB_STORAGE;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum MemError {
    #[from]
    Confinement(confinement::Error),
}

//////////
// STASH
//////////

/// Hoard is an in-memory stash useful for WASM implementations.
#[derive(Getters, Debug)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemStash {
    schemata: TinyOrdMap<SchemaId, Schema>,
    geneses: SmallOrdMap<ContractId, Genesis>,
    bundles: LargeOrdMap<BundleId, TransitionBundle>,
    witnesses: LargeOrdMap<Txid, SealWitness>,
    secret_seals: LargeOrdSet<GraphSeal>,
    type_system: TypeSystem,
    libs: SmallOrdMap<LibId, Lib>,
}

impl StrictSerialize for MemStash {}
impl StrictDeserialize for MemStash {}

impl MemStash {
    pub fn in_memory() -> Self {
        Self {
            schemata: empty!(),
            geneses: empty!(),
            bundles: empty!(),
            witnesses: empty!(),
            secret_seals: empty!(),
            type_system: none!(),
            libs: empty!(),
        }
    }
}

//////////
// STATE
//////////

#[derive(Getters, Debug)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemState {
    witnesses: LargeOrdMap<Txid, WitnessOrd>,
    invalid_ops: LargeOrdSet<OpId>,
    contracts: SmallOrdMap<ContractId, MemContractState>,
}

impl StrictSerialize for MemState {}
impl StrictDeserialize for MemState {}

impl MemState {
    pub fn in_memory() -> Self {
        Self {
            witnesses: empty!(),
            invalid_ops: empty!(),
            contracts: empty!(),
        }
    }
}

#[derive(Getters, Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct MemGlobalState {
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    known: LargeOrdMap<GlobalOut, RevealedData>,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::small_int"))]
    limit: u24,
}

impl MemGlobalState {
    pub fn new(limit: u24) -> Self {
        MemGlobalState {
            known: empty!(),
            limit,
        }
    }
}

/// Contract history accumulates raw data from the contract history, extracted
/// from a series of consignments over the time. It does consensus ordering of
/// the state data, but it doesn't interpret or validates the state against the
/// schema.
///
/// NB: MemContract provides an in-memory contract state used during contract
/// validation. It does not support filtering by witness transaction validity
/// and thus must not be used in any other cases in its explicit form. Pls see
/// [`MemContract`] instead.
#[derive(Getters, Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct MemContractState {
    #[getter(as_copy)]
    schema_id: SchemaId,
    #[getter(as_copy)]
    contract_id: ContractId,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    #[getter(skip)]
    global: TinyOrdMap<GlobalStateType, MemGlobalState>,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    rights: LargeOrdSet<OutputAssignment<VoidState>>,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    fungibles: LargeOrdSet<OutputAssignment<RevealedValue>>,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    data: LargeOrdSet<OutputAssignment<RevealedData>>,
}

impl MemContractState {
    pub fn new(schema: &Schema, contract_id: ContractId) -> Self {
        let global = TinyOrdMap::from_iter_checked(
            schema
                .global_types
                .iter()
                .map(|(ty, glob)| (*ty, MemGlobalState::new(glob.global_state_schema.max_items))),
        );
        MemContractState {
            schema_id: schema.schema_id(),
            contract_id,
            global,
            rights: empty!(),
            fungibles: empty!(),
            data: empty!(),
        }
    }

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

pub struct MemContract<M: Borrow<MemContractState> = MemContractState> {
    filter: HashMap<Txid, WitnessOrd>,
    invalid_ops: BTreeSet<OpId>,
    unfiltered: M,
}

impl<M: Borrow<MemContractState>> MemContract<M> {
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

impl<M: Borrow<MemContractState>> Debug for MemContract<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemContractFiltered { .. }")
    }
}

struct MemGlobalStateAccess {
    values: Vec<Rc<GlobalStateEntry>>,
    last_idx: Option<u24>,
}

impl MemGlobalStateAccess {
    fn new(items: impl Iterator<Item = (GlobalOrd, RevealedData)>, limit: u24) -> Self {
        let mut values = items
            .take(limit.to_usize())
            .map(|(ord, data)| GlobalStateEntry::new(ord, data))
            .map(Rc::new)
            .collect::<Vec<_>>();
        values.sort();
        values.reverse();
        Self {
            values,
            last_idx: None,
        }
    }
}

impl Iterator for MemGlobalStateAccess {
    type Item = Rc<GlobalStateEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(last_idx) = self.last_idx.as_mut() {
            *last_idx += u24::ONE;
        } else {
            self.last_idx = Some(u24::ZERO);
        }
        self.values.get(self.last_idx?.into_usize()).map(Rc::clone)
    }

    #[inline]
    fn count(self) -> usize { self.values.len() }
}

impl GlobalsIter for MemGlobalStateAccess {
    fn at_depth(&self, depth: usize) -> Option<Self::Item> {
        let depth = u24::try_from(depth as u32).ok()?;
        let entry = self.values.get(depth.to_usize())?;
        Some(Rc::clone(entry))
    }
}

impl<M: Borrow<MemContractState>> ContractStateAccess for MemContract<M> {
    fn global(
        &self,
        ty: GlobalStateType,
    ) -> Result<impl GlobalsIter<Item = impl Borrow<GlobalStateEntry>>, UnknownGlobalStateType>
    {
        let state = self
            .unfiltered
            .borrow()
            .global
            .get(&ty)
            .ok_or(UnknownGlobalStateType(ty))?;
        let items = state
            .known
            .as_unconfined()
            .iter()
            .rev()
            .filter_map(|(out, data)| {
                let ord = match out.op_witness {
                    OpWitness::Genesis => GlobalOrd::genesis(out.index),
                    OpWitness::Transition(id, ty) => {
                        // skip globals for which we don't have a WitnessOrd
                        let ord = self.filter.get(&id)?;
                        GlobalOrd::transition(out.opid, out.index, ty, out.nonce, *ord)
                    }
                };
                Some((ord, data.to_owned()))
            });
        Ok(MemGlobalStateAccess::new(items, state.limit))
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

impl ContractStateEvolve for MemContract<MemContractState> {
    type Context<'ctx> = (&'ctx Schema, ContractId);
    type Error = MemError;

    fn init(context: Self::Context<'_>) -> Self {
        Self {
            filter: empty!(),
            invalid_ops: empty!(),
            unfiltered: MemContractState::new(context.0, context.1),
        }
    }

    fn evolve_state(&mut self, op: OrdOpRef) -> Result<(), Self::Error> {
        fn writer(me: &mut MemContract<MemContractState>) -> MemContractWriter<'_> {
            MemContractWriter {
                writer: Box::new(
                    |witness_id: Txid, ord: WitnessOrd| -> Result<(), confinement::Error> {
                        // NB: We do not check the existence of the witness since we have a
                        // newer version anyway and even if it is
                        // known we have to replace it
                        me.filter.insert(witness_id, ord);
                        Ok(())
                    },
                ),
                contract: &mut me.unfiltered,
            }
        }
        match op {
            OrdOpRef::Genesis(genesis) => {
                let mut writer = writer(self);
                writer.add_genesis(genesis)
            }
            OrdOpRef::Transition(transition, witness_id, ord, bundle_id) => {
                let mut writer = writer(self);
                writer.add_transition(transition, witness_id, ord, bundle_id)
            }
        }?;
        Ok(())
    }
}

impl<M: Borrow<MemContractState>> ContractStateRead for MemContract<M> {
    type Error = Infallible;

    #[inline]
    fn contract_id(&self) -> ContractId { self.unfiltered.borrow().contract_id }

    #[inline]
    fn schema_id(&self) -> SchemaId { self.unfiltered.borrow().schema_id }

    #[inline]
    fn witness_ord(&self, witness_id: Txid) -> Option<WitnessOrd> {
        self.filter.get(&witness_id).copied()
    }

    #[inline]
    fn rights_all(
        &self,
    ) -> impl Iterator<Item = Result<OutputAssignment<VoidState>, Self::Error>> + '_ {
        self.unfiltered
            .borrow()
            .rights
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_op(&self.invalid_ops))
            .cloned()
            .map(Ok)
    }

    #[inline]
    fn fungible_all(
        &self,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedValue>, Self::Error>> + '_ {
        self.unfiltered
            .borrow()
            .fungibles
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_op(&self.invalid_ops))
            .cloned()
            .map(Ok)
    }

    #[inline]
    fn data_all(
        &self,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedData>, Self::Error>> + '_ {
        self.unfiltered
            .borrow()
            .data
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_op(&self.invalid_ops))
            .cloned()
            .map(Ok)
    }
}

pub struct MemContractWriter<'mem> {
    writer: Box<dyn FnMut(Txid, WitnessOrd) -> Result<(), confinement::Error> + 'mem>,
    contract: &'mem mut MemContractState,
}

impl ContractStateWrite for MemContractWriter<'_> {
    type Error = MemError;

    /// # Panics
    ///
    /// If genesis violates RGB consensus rules and wasn't checked against the
    /// schema before adding to the history.
    fn add_genesis(&mut self, genesis: &Genesis) -> Result<(), Self::Error> {
        self.contract.add_operation(OrdOpRef::Genesis(genesis));
        Ok(())
    }

    /// # Panics
    ///
    /// If state transition violates RGB consensus rules and wasn't checked
    /// against the schema before adding to the history.
    fn add_transition(
        &mut self,
        transition: &Transition,
        witness_id: Txid,
        ord: WitnessOrd,
        bundle_id: BundleId,
    ) -> Result<(), Self::Error> {
        (self.writer)(witness_id, ord)?;
        self.contract
            .add_operation(OrdOpRef::Transition(transition, witness_id, ord, bundle_id));
        Ok(())
    }
}

//////////
// INDEX
//////////

impl From<confinement::Error> for IndexReadError<confinement::Error> {
    fn from(err: confinement::Error) -> Self { IndexReadError::Connectivity(err) }
}

impl From<confinement::Error> for IndexWriteError<confinement::Error> {
    fn from(err: confinement::Error) -> Self { IndexWriteError::Connectivity(err) }
}

#[derive(Clone, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractIndex {
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    public_opouts: LargeOrdSet<Opout>,
    #[cfg_attr(feature = "serde", serde(with = "outpoint_opouts_serde"))]
    outpoint_opouts: LargeOrdMap<OutputSeal, MediumOrdSet<Opout>>,
}

/// Serde support for the `outpoint_opouts` field, which nests a `Confined` collection inside
/// another one and thus can't use the generic `strict_encoding::serde_helpers::confined` helper.
#[cfg(feature = "serde")]
mod outpoint_opouts_serde {
    use std::collections::BTreeMap;

    use serde_crate::de::Error;
    use serde_crate::{Deserialize, Deserializer, Serializer};

    use super::*;

    type Map = LargeOrdMap<OutputSeal, MediumOrdSet<Opout>>;

    pub fn serialize<S>(map: &Map, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        // using collect_map to avoid unnecessary memory allocation
        serializer.collect_map(
            map.iter()
                .map(|(seal, opouts)| (seal, opouts.as_unconfined())),
        )
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Map, D::Error>
    where D: Deserializer<'de> {
        let unconfined = BTreeMap::<OutputSeal, BTreeSet<Opout>>::deserialize(deserializer)?;
        let mut map = BTreeMap::new();
        for (seal, opouts) in unconfined {
            map.insert(seal, MediumOrdSet::try_from(opouts).map_err(D::Error::custom)?);
        }
        Map::try_from(map).map_err(D::Error::custom)
    }
}

impl DefaultBasedStrictDumb for ContractIndex {}

#[derive(Getters, Debug)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemIndex {
    op_bundle_children_index: LargeOrdMap<OpId, SmallOrdSet<BundleId>>,
    op_bundle_index: LargeOrdMap<OpId, BundleId>,
    bundle_contract_index: LargeOrdMap<BundleId, ContractId>,
    bundle_witness_index: LargeOrdMap<BundleId, LargeOrdSet<Txid>>,
    contract_index: SmallOrdMap<ContractId, ContractIndex>,
    terminal_index: LargeOrdMap<SecretSeal, MediumOrdSet<Opout>>,
}

impl StrictSerialize for MemIndex {}
impl StrictDeserialize for MemIndex {}

impl MemIndex {
    pub fn in_memory() -> Self {
        Self {
            op_bundle_children_index: empty!(),
            op_bundle_index: empty!(),
            bundle_contract_index: empty!(),
            bundle_witness_index: empty!(),
            contract_index: empty!(),
            terminal_index: empty!(),
        }
    }
}
