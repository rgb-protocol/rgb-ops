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
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::{iter, mem};

use aluvm::library::{Lib, LibId};
use amplify::confinement::{
    self, LargeOrdMap, LargeOrdSet, MediumOrdSet, SmallOrdMap, SmallOrdSet, TinyOrdMap,
};
use amplify::num::u24;
use bp::dbc::tapret::TapretCommitment;
use bp::{Outpoint, Txid};
use commit_verify::{CommitId, Conceal};
use nonasync::persistence::{CloneNoPersistence, Persistence, PersistenceError, Persisting};
use rgb::validation::DbcProof;
use rgb::vm::{
    ContractStateAccess, ContractStateEvolve, GlobalContractState, GlobalOrd, GlobalStateIter,
    OrdOpRef, UnknownGlobalStateType, WitnessOrd,
};
use rgb::{
    Assign, AssignmentType, Assignments, AssignmentsRef, BundleId, ContractId, ExposedSeal,
    ExposedState, FungibleState, Genesis, GenesisSeal, GlobalStateType, GraphSeal, OpId, Operation,
    Opout, OutputSeal, RevealedData, RevealedValue, Schema, SchemaId, SecretSeal, Transition,
    TransitionBundle, TypedAssigns, VoidState,
};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::TypeSystem;

use super::{
    ContractStateRead, ContractStateWrite, IndexInconsistency, IndexProvider, IndexReadError,
    IndexReadProvider, IndexWriteError, IndexWriteProvider, StashInconsistency, StashProvider,
    StashProviderError, StashReadProvider, StashWriteProvider, StateInconsistency, StateProvider,
    StateReadProvider, StateWriteProvider, StoreTransaction,
};
use crate::containers::SealWitness;
use crate::contract::{GlobalOut, KnownState, OpWitness, OutputAssignment};
use crate::LIB_NAME_RGB_STORAGE;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum MemError {
    #[from]
    Persistence(PersistenceError),

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
    #[getter(skip)]
    #[strict_type(skip)]
    persistence: Option<Persistence<Self>>,

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
            persistence: none!(),
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

impl CloneNoPersistence for MemStash {
    fn clone_no_persistence(&self) -> Self {
        Self {
            persistence: None,
            schemata: self.schemata.clone(),
            geneses: self.geneses.clone(),
            bundles: self.bundles.clone(),
            witnesses: self.witnesses.clone(),
            secret_seals: self.secret_seals.clone(),
            type_system: self.type_system.clone(),
            libs: self.libs.clone(),
        }
    }
}

impl Persisting for MemStash {
    #[inline]
    fn persistence(&self) -> Option<&Persistence<Self>> { self.persistence.as_ref() }
    #[inline]
    fn persistence_mut(&mut self) -> Option<&mut Persistence<Self>> { self.persistence.as_mut() }
    #[inline]
    fn as_mut_persistence(&mut self) -> &mut Option<Persistence<Self>> { &mut self.persistence }
}

impl StoreTransaction for MemStash {
    type TransactionErr = MemError;
    #[inline]
    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.mark_dirty();
        Ok(())
    }
    #[inline]
    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> { Ok(self.store()?) }
    #[inline]
    fn rollback_transaction(&mut self) { unreachable!() }
}

impl StashProvider for MemStash {}

impl StashReadProvider for MemStash {
    // With in-memory data we have no connectivity or I/O errors
    type Error = Infallible;

    fn type_system(&self) -> Result<&TypeSystem, Self::Error> { Ok(&self.type_system) }

    fn lib(&self, id: LibId) -> Result<&Lib, StashProviderError<Self::Error>> {
        self.libs
            .get(&id)
            .ok_or_else(|| StashInconsistency::LibAbsent(id).into())
    }

    fn schemata(&self) -> Result<impl Iterator<Item = &Schema>, Self::Error> {
        Ok(self.schemata.values())
    }

    fn schema(&self, schema_id: SchemaId) -> Result<&Schema, StashProviderError<Self::Error>> {
        self.schemata
            .get(&schema_id)
            .ok_or_else(|| StashInconsistency::SchemaAbsent(schema_id).into())
    }

    fn geneses(&self) -> Result<impl Iterator<Item = &Genesis>, Self::Error> {
        Ok(self.geneses.values())
    }

    fn genesis(
        &self,
        contract_id: ContractId,
    ) -> Result<&Genesis, StashProviderError<Self::Error>> {
        self.geneses
            .get(&contract_id)
            .ok_or(StashInconsistency::ContractAbsent(contract_id).into())
    }

    fn witness_ids(&self) -> Result<impl Iterator<Item = Txid>, Self::Error> {
        Ok(self.witnesses.keys().copied())
    }

    fn bundle_ids(&self) -> Result<impl Iterator<Item = BundleId>, Self::Error> {
        Ok(self.bundles.keys().copied())
    }

    fn bundle(
        &self,
        bundle_id: BundleId,
    ) -> Result<&TransitionBundle, StashProviderError<Self::Error>> {
        self.bundles
            .get(&bundle_id)
            .ok_or(StashInconsistency::BundleAbsent(bundle_id).into())
    }

    fn witness(&self, witness_id: Txid) -> Result<&SealWitness, StashProviderError<Self::Error>> {
        self.witnesses
            .get(&witness_id)
            .ok_or(StashInconsistency::WitnessAbsent(witness_id).into())
    }

    fn taprets(&self) -> Result<impl Iterator<Item = (Txid, TapretCommitment)>, Self::Error> {
        Ok(self
            .witnesses
            .iter()
            .filter_map(|(witness_id, witness)| match &witness.dbc_proof {
                DbcProof::Tapret(tapret_proof) => Some((*witness_id, TapretCommitment {
                    mpc: witness.merkle_block.commit_id(),
                    nonce: tapret_proof.path_proof.nonce(),
                })),
                _ => None,
            }))
    }

    fn seal_secret(&self, secret: SecretSeal) -> Result<Option<GraphSeal>, Self::Error> {
        Ok(self
            .secret_seals
            .iter()
            .find(|s| s.conceal() == secret)
            .copied())
    }

    fn secret_seals(&self) -> Result<impl Iterator<Item = GraphSeal>, Self::Error> {
        Ok(self.secret_seals.iter().copied())
    }
}

impl StashWriteProvider for MemStash {
    type Error = MemError;

    fn replace_schema(&mut self, schema: Schema) -> Result<bool, Self::Error> {
        let schema_id = schema.schema_id();
        if !self.schemata.contains_key(&schema_id) {
            self.schemata.insert(schema_id, schema)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn replace_genesis(&mut self, genesis: Genesis) -> Result<bool, Self::Error> {
        let contract_id = genesis.contract_id();
        let present = self.geneses.insert(contract_id, genesis)?.is_some();
        Ok(!present)
    }

    fn replace_bundle(&mut self, bundle: TransitionBundle) -> Result<bool, Self::Error> {
        let bundle_id = bundle.bundle_id();
        let present = self.bundles.insert(bundle_id, bundle)?.is_some();
        Ok(!present)
    }

    fn replace_witness(&mut self, witness: SealWitness) -> Result<bool, Self::Error> {
        let witness_id = witness.witness_id();
        let present = self.witnesses.insert(witness_id, witness)?.is_some();
        Ok(!present)
    }

    fn consume_types(&mut self, types: TypeSystem) -> Result<(), Self::Error> {
        Ok(self.type_system.extend(types)?)
    }

    fn replace_lib(&mut self, lib: Lib) -> Result<bool, Self::Error> {
        let present = self.libs.insert(lib.id(), lib)?.is_some();
        Ok(!present)
    }

    fn add_secret_seal(&mut self, seal: GraphSeal) -> Result<bool, Self::Error> {
        let present = self.secret_seals.contains(&seal);
        self.secret_seals.push(seal)?;
        Ok(!present)
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
    #[getter(skip)]
    #[strict_type(skip)]
    persistence: Option<Persistence<Self>>,

    witnesses: LargeOrdMap<Txid, WitnessOrd>,
    invalid_bundles: LargeOrdSet<BundleId>,
    contracts: SmallOrdMap<ContractId, MemContractState>,
}

impl StrictSerialize for MemState {}
impl StrictDeserialize for MemState {}

impl MemState {
    pub fn in_memory() -> Self {
        Self {
            persistence: none!(),
            witnesses: empty!(),
            invalid_bundles: empty!(),
            contracts: empty!(),
        }
    }
}

impl CloneNoPersistence for MemState {
    fn clone_no_persistence(&self) -> Self {
        Self {
            persistence: None,
            witnesses: self.witnesses.clone(),
            invalid_bundles: empty!(),
            contracts: self.contracts.clone(),
        }
    }
}

impl Persisting for MemState {
    #[inline]
    fn persistence(&self) -> Option<&Persistence<Self>> { self.persistence.as_ref() }
    #[inline]
    fn persistence_mut(&mut self) -> Option<&mut Persistence<Self>> { self.persistence.as_mut() }
    #[inline]
    fn as_mut_persistence(&mut self) -> &mut Option<Persistence<Self>> { &mut self.persistence }
}

impl StoreTransaction for MemState {
    type TransactionErr = MemError;
    #[inline]
    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.mark_dirty();
        Ok(())
    }
    #[inline]
    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> { Ok(self.store()?) }
    #[inline]
    fn rollback_transaction(&mut self) { unreachable!() }
}

impl StateProvider for MemState {}

impl StateReadProvider for MemState {
    type ContractRead<'a> = MemContract<&'a MemContractState>;
    type Error = StateInconsistency;

    fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<Self::ContractRead<'_>, Self::Error> {
        let unfiltered = self
            .contracts
            .get(&contract_id)
            .ok_or(StateInconsistency::UnknownContract(contract_id))?;
        let filter = self
            .witnesses
            .iter()
            .filter(|(id, _)| {
                let id = Some(**id);
                unfiltered
                    .global
                    .values()
                    .flat_map(|state| state.known.keys())
                    .any(|out| out.witness_id() == id)
                    || unfiltered.rights.iter().any(|a| a.witness == id)
                    || unfiltered.fungibles.iter().any(|a| a.witness == id)
                    || unfiltered.data.iter().any(|a| a.witness == id)
            })
            .map(|(id, ord)| (*id, *ord))
            .collect();
        Ok(MemContract {
            filter,
            invalid_bundles: self.invalid_bundles.clone().release(),
            unfiltered,
        })
    }

    fn witnesses(&self) -> LargeOrdMap<Txid, WitnessOrd> { self.witnesses.clone() }

    fn invalid_bundles(&self) -> LargeOrdSet<BundleId> { self.invalid_bundles.clone() }
}

impl StateWriteProvider for MemState {
    type ContractWrite<'a> = MemContractWriter<'a>;
    type Error = MemError;

    fn register_contract(
        &mut self,
        schema: &Schema,
        genesis: &Genesis,
    ) -> Result<Self::ContractWrite<'_>, Self::Error> {
        // TODO: Add begin/commit transaction
        let contract_id = genesis.contract_id();
        // This crazy construction is caused by a stupidity of rust borrow checker
        let contract = if self.contracts.contains_key(&contract_id) {
            if let Some(contract) = self.contracts.get_mut(&contract_id) {
                contract
            } else {
                unreachable!();
            }
        } else {
            self.contracts
                .insert(contract_id, MemContractState::new(schema, contract_id))?;
            self.contracts.get_mut(&contract_id).expect("just inserted")
        };
        let mut writer = MemContractWriter {
            writer: Box::new(
                |witness_id: Txid, ord: WitnessOrd| -> Result<(), confinement::Error> {
                    // NB: We do not check the existence of the witness since we have a newer
                    // version anyway and even if it is known we have to replace it
                    self.witnesses.insert(witness_id, ord)?;
                    Ok(())
                },
            ),
            contract,
        };
        writer.add_genesis(genesis)?;
        Ok(writer)
    }

    fn update_contract(
        &mut self,
        contract_id: ContractId,
    ) -> Result<Option<Self::ContractWrite<'_>>, Self::Error> {
        // TODO: Add begin/commit transaction
        Ok(self
            .contracts
            .get_mut(&contract_id)
            .map(|contract| MemContractWriter {
                // We can't move this constructor to a dedicated method due to the rust borrower
                // checker
                writer: Box::new(
                    |witness_id: Txid, ord: WitnessOrd| -> Result<(), confinement::Error> {
                        // NB: We do not check the existence of the witness since we have a newer
                        // version anyway and even if it is known we have to replace
                        // it
                        self.witnesses.insert(witness_id, ord)?;
                        Ok(())
                    },
                ),
                contract,
            }))
    }

    fn upsert_witness(
        &mut self,
        witness_id: Txid,
        witness_ord: WitnessOrd,
    ) -> Result<(), Self::Error> {
        self.witnesses.insert(witness_id, witness_ord)?;
        Ok(())
    }

    fn update_bundle(&mut self, bundle_id: BundleId, valid: bool) -> Result<(), Self::Error> {
        if valid {
            self.invalid_bundles.remove(&bundle_id)?;
        } else {
            self.invalid_bundles.push(bundle_id)?;
        }
        Ok(())
    }
}

#[derive(Getters, Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct MemGlobalState {
    known: LargeOrdMap<GlobalOut, RevealedData>,
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
    #[getter(skip)]
    global: TinyOrdMap<GlobalStateType, MemGlobalState>,
    rights: LargeOrdSet<OutputAssignment<VoidState>>,
    fungibles: LargeOrdSet<OutputAssignment<RevealedValue>>,
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

    fn add_operation(&mut self, op: OrdOpRef) {
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
    invalid_bundles: BTreeSet<BundleId>,
    unfiltered: M,
}

impl<M: Borrow<MemContractState>> Debug for MemContract<M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemContractFiltered { .. }")
    }
}

impl<M: Borrow<MemContractState>> ContractStateAccess for MemContract<M> {
    fn global(
        &self,
        ty: GlobalStateType,
    ) -> Result<GlobalContractState<impl GlobalStateIter>, UnknownGlobalStateType> {
        type Src<'a> = &'a BTreeMap<GlobalOut, RevealedData>;
        type FilteredIter<'a> = Box<dyn Iterator<Item = (GlobalOrd, &'a RevealedData)> + 'a>;
        struct Iter<'a> {
            src: Src<'a>,
            iter: FilteredIter<'a>,
            last: Option<(GlobalOrd, &'a RevealedData)>,
            depth: u24,
            constructor: Box<dyn Fn(Src<'a>) -> FilteredIter<'a> + 'a>,
        }
        impl<'a> Iter<'a> {
            fn swap(&mut self) -> FilteredIter<'a> {
                let mut iter = (self.constructor)(self.src);
                mem::swap(&mut iter, &mut self.iter);
                iter
            }
        }
        impl<'a> GlobalStateIter for Iter<'a> {
            type Data = &'a RevealedData;
            fn size(&mut self) -> u24 {
                let iter = self.swap();
                // TODO: Consuming iterator just to count items is highly inefficient, but I do
                //       not know any other way of computing this value
                let size = iter.count();
                u24::try_from(size as u32).expect("iterator size must fit u24 due to `take` limit")
            }
            fn prev(&mut self) -> Option<(GlobalOrd, Self::Data)> {
                self.last = self.iter.next();
                self.depth += u24::ONE;
                self.last()
            }
            fn last(&mut self) -> Option<(GlobalOrd, Self::Data)> { self.last }
            fn reset(&mut self, depth: u24) {
                match self.depth.cmp(&depth) {
                    Ordering::Less => {
                        let mut iter = Box::new(iter::empty()) as FilteredIter;
                        mem::swap(&mut self.iter, &mut iter);
                        self.iter = Box::new(iter.skip(depth.to_usize() - depth.to_usize()))
                    }
                    Ordering::Equal => {}
                    Ordering::Greater => {
                        let iter = self.swap();
                        self.iter = Box::new(iter.skip(depth.to_usize()));
                    }
                }
            }
        }
        // We need this due to the limitations of the rust compiler to enforce lifetimes
        // on closures
        fn constrained<'a, F: Fn(Src<'a>) -> FilteredIter<'a>>(f: F) -> F { f }

        let state = self
            .unfiltered
            .borrow()
            .global
            .get(&ty)
            .ok_or(UnknownGlobalStateType(ty))?;

        let constructor = constrained(move |src: Src<'_>| -> FilteredIter<'_> {
            Box::new(
                src.iter()
                    .rev()
                    .filter_map(|(out, data)| {
                        let ord = match out.op_witness {
                            OpWitness::Genesis => GlobalOrd::genesis(out.index),
                            OpWitness::Transition(id, ty) => {
                                let ord = self.filter.get(&id)?;
                                GlobalOrd::transition(out.opid, out.index, ty, out.nonce, *ord)
                            }
                        };
                        Some((ord, data))
                    })
                    .take(state.limit.to_usize()),
            )
        });
        let iter = Iter {
            src: state.known.as_unconfined(),
            iter: constructor(state.known.as_unconfined()),
            depth: u24::ZERO,
            last: None,
            constructor: Box::new(constructor),
        };
        Ok(GlobalContractState::new(iter))
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
            .filter(|assignment| assignment.check_bundle(&self.invalid_bundles))
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
            .filter(|assignment| assignment.check_bundle(&self.invalid_bundles))
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
            .filter(|assignment| assignment.check_bundle(&self.invalid_bundles))
            .map(|assignment| &assignment.state)
    }
}

impl ContractStateEvolve for MemContract<MemContractState> {
    type Context<'ctx> = (&'ctx Schema, ContractId);
    type Error = MemError;

    fn init(context: Self::Context<'_>) -> Self {
        Self {
            filter: empty!(),
            invalid_bundles: empty!(),
            unfiltered: MemContractState::new(context.0, context.1),
        }
    }

    fn evolve_state(&mut self, op: OrdOpRef) -> Result<(), Self::Error> {
        fn writer(me: &mut MemContract<MemContractState>) -> MemContractWriter {
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
    #[inline]
    fn contract_id(&self) -> ContractId { self.unfiltered.borrow().contract_id }

    #[inline]
    fn schema_id(&self) -> SchemaId { self.unfiltered.borrow().schema_id }

    #[inline]
    fn witness_ord(&self, witness_id: Txid) -> Option<WitnessOrd> {
        self.filter.get(&witness_id).copied()
    }

    #[inline]
    fn rights_all(&self) -> impl Iterator<Item = &OutputAssignment<VoidState>> {
        self.unfiltered
            .borrow()
            .rights
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_bundle(&self.invalid_bundles))
    }

    #[inline]
    fn fungible_all(&self) -> impl Iterator<Item = &OutputAssignment<RevealedValue>> {
        self.unfiltered
            .borrow()
            .fungibles
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_bundle(&self.invalid_bundles))
    }

    #[inline]
    fn data_all(&self) -> impl Iterator<Item = &OutputAssignment<RevealedData>> {
        self.unfiltered
            .borrow()
            .data
            .iter()
            .filter(|assignment| assignment.check_witness(&self.filter))
            .filter(|assignment| assignment.check_bundle(&self.invalid_bundles))
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
    public_opouts: LargeOrdSet<Opout>,
    outpoint_opouts: LargeOrdMap<OutputSeal, MediumOrdSet<Opout>>,
}

#[derive(Getters, Debug)]
#[getter(prefix = "debug_")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemIndex {
    #[getter(skip)]
    #[strict_type(skip)]
    persistence: Option<Persistence<Self>>,

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
            persistence: None,
            op_bundle_children_index: empty!(),
            op_bundle_index: empty!(),
            bundle_contract_index: empty!(),
            bundle_witness_index: empty!(),
            contract_index: empty!(),
            terminal_index: empty!(),
        }
    }
}

impl CloneNoPersistence for MemIndex {
    fn clone_no_persistence(&self) -> Self {
        Self {
            persistence: None,
            op_bundle_children_index: self.op_bundle_children_index.clone(),
            op_bundle_index: self.op_bundle_index.clone(),
            bundle_contract_index: self.bundle_contract_index.clone(),
            bundle_witness_index: self.bundle_witness_index.clone(),
            contract_index: self.contract_index.clone(),
            terminal_index: self.terminal_index.clone(),
        }
    }
}

impl Persisting for MemIndex {
    #[inline]
    fn persistence(&self) -> Option<&Persistence<Self>> { self.persistence.as_ref() }
    #[inline]
    fn persistence_mut(&mut self) -> Option<&mut Persistence<Self>> { self.persistence.as_mut() }
    #[inline]
    fn as_mut_persistence(&mut self) -> &mut Option<Persistence<Self>> { &mut self.persistence }
}

impl StoreTransaction for MemIndex {
    type TransactionErr = MemError;
    #[inline]
    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.mark_dirty();
        Ok(())
    }
    #[inline]
    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> { Ok(self.store()?) }
    #[inline]
    fn rollback_transaction(&mut self) { unreachable!() }
}

impl IndexProvider for MemIndex {}

impl IndexReadProvider for MemIndex {
    type Error = Infallible;

    fn contracts_assigning(
        &self,
        outpoints: BTreeSet<Outpoint>,
    ) -> Result<impl Iterator<Item = ContractId> + '_, Self::Error> {
        Ok(self
            .contract_index
            .iter()
            .flat_map(move |(contract_id, index)| {
                outpoints.clone().into_iter().filter_map(|outpoint| {
                    if index
                        .outpoint_opouts
                        .keys()
                        .any(|seal| seal.to_outpoint() == outpoint)
                    {
                        Some(*contract_id)
                    } else {
                        None
                    }
                })
            }))
    }

    fn public_opouts(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;
        Ok(index.public_opouts.to_unconfined())
    }

    fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>> {
        let index = self
            .contract_index
            .get(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;
        let mut opouts = BTreeSet::new();
        for output in outpoints.into_iter().map(|o| o.into()) {
            let set = index
                .outpoint_opouts
                .iter()
                .find(|(seal, _)| seal.to_outpoint() == output)
                .map(|(_, set)| set.to_unconfined())
                .ok_or(IndexInconsistency::OutpointUnknown(output, contract_id))?;
            opouts.extend(set)
        }
        Ok(opouts)
    }

    fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = SecretSeal>,
    ) -> Result<BTreeSet<Opout>, Self::Error> {
        let terminals = terminals.into_iter().collect::<BTreeSet<_>>();
        Ok(self
            .terminal_index
            .iter()
            .filter(|(seal, _)| terminals.contains(*seal))
            .flat_map(|(_, opout)| opout.iter())
            .copied()
            .collect())
    }

    fn bundle_id_for_op(&self, opid: OpId) -> Result<BundleId, IndexReadError<Self::Error>> {
        self.op_bundle_index
            .get(&opid)
            .copied()
            .ok_or(IndexInconsistency::BundleAbsent(opid).into())
    }

    fn bundle_ids_children_of_op(
        &self,
        opid: OpId,
    ) -> Result<SmallOrdSet<BundleId>, IndexReadError<Self::Error>> {
        self.op_bundle_children_index
            .get(&opid)
            .ok_or(IndexInconsistency::BundleAbsent(opid).into())
            .cloned()
    }

    fn bundle_info(
        &self,
        bundle_id: BundleId,
    ) -> Result<(impl Iterator<Item = Txid>, ContractId), IndexReadError<Self::Error>> {
        let witness_id = self
            .bundle_witness_index
            .get(&bundle_id)
            .ok_or(IndexInconsistency::BundleWitnessUnknown(bundle_id))?;
        let contract_id = self
            .bundle_contract_index
            .get(&bundle_id)
            .ok_or(IndexInconsistency::BundleContractUnknown(bundle_id))?;
        Ok((witness_id.iter().cloned(), *contract_id))
    }
}

impl IndexWriteProvider for MemIndex {
    type Error = MemError;

    fn register_contract(&mut self, contract_id: ContractId) -> Result<bool, Self::Error> {
        if !self.contract_index.contains_key(&contract_id) {
            self.contract_index.insert(contract_id, empty!())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn register_bundle(
        &mut self,
        bundle_id: BundleId,
        witness_id: Txid,
        contract_id: ContractId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        if let Some(alt) = self
            .bundle_contract_index
            .get(&bundle_id)
            .filter(|alt| *alt != &contract_id)
        {
            return Err(IndexInconsistency::DistinctBundleContract {
                bundle_id,
                present: *alt,
                expected: contract_id,
            }
            .into());
        }
        self.bundle_witness_index
            .entry(bundle_id)?
            .or_default()
            .push(witness_id)?;
        let present2 = self
            .bundle_contract_index
            .insert(bundle_id, contract_id)?
            .is_some();
        Ok(!present2)
    }

    fn register_operation(
        &mut self,
        opid: OpId,
        bundle_id: BundleId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        if let Some(alt) = self
            .op_bundle_index
            .get(&opid)
            .filter(|alt| *alt != &bundle_id)
        {
            return Err(IndexInconsistency::DistinctBundleOp {
                opid,
                present: *alt,
                expected: bundle_id,
            }
            .into());
        }
        let present = self.op_bundle_index.insert(opid, bundle_id)?.is_some();
        Ok(!present)
    }

    fn register_spending(
        &mut self,
        opid: OpId,
        bundle_id: BundleId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        let mut present = false;
        match self.op_bundle_children_index.get_mut(&opid) {
            Some(opids) => {
                present = true;
                opids.push(bundle_id)?;
            }
            None => {
                self.op_bundle_children_index
                    .insert(opid, small_bset!(bundle_id))?;
            }
        }
        Ok(present)
    }

    fn index_genesis_assignments<State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        vec: &[Assign<State, GenesisSeal>],
        opid: OpId,
        type_id: AssignmentType,
    ) -> Result<(), IndexWriteError<Self::Error>> {
        let index = self
            .contract_index
            .get_mut(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;

        for (no, assign) in vec.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::Revealed { seal, .. } = assign {
                let output = seal
                    .to_output_seal()
                    .expect("genesis seals always have outpoint");
                match index.outpoint_opouts.get_mut(&output) {
                    Some(opouts) => {
                        opouts.push(opout)?;
                    }
                    None => {
                        index.outpoint_opouts.insert(output, medium_bset!(opout))?;
                    }
                }
            }
        }

        // We need two cycles due to the borrow checker
        self.extend_terminals(vec, opid, type_id)
    }

    fn index_transition_assignments<State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        vec: &[Assign<State, GraphSeal>],
        opid: OpId,
        type_id: AssignmentType,
        witness_id: Txid,
    ) -> Result<(), IndexWriteError<Self::Error>> {
        let index = self
            .contract_index
            .get_mut(&contract_id)
            .ok_or(IndexInconsistency::ContractAbsent(contract_id))?;

        for (no, assign) in vec.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::Revealed { seal, .. } = assign {
                let output = seal.to_output_seal_or_default(witness_id);
                match index.outpoint_opouts.get_mut(&output) {
                    Some(opouts) => {
                        opouts.push(opout)?;
                    }
                    None => {
                        index.outpoint_opouts.insert(output, medium_bset!(opout))?;
                    }
                }
            }
        }

        // We need two cycles due to the borrow checker
        self.extend_terminals(vec, opid, type_id)
    }
}

impl MemIndex {
    fn extend_terminals<State: ExposedState, Seal: ExposedSeal>(
        &mut self,
        vec: &[Assign<State, Seal>],
        opid: OpId,
        type_id: AssignmentType,
    ) -> Result<(), IndexWriteError<MemError>> {
        for (no, assign) in vec.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            if let Assign::ConfidentialSeal { seal, .. } = assign {
                self.add_terminal(*seal, opout)?;
            }
        }
        Ok(())
    }

    fn add_terminal(
        &mut self,
        seal: SecretSeal,
        opout: Opout,
    ) -> Result<(), IndexWriteError<MemError>> {
        match self
            .terminal_index
            .remove(&seal)
            .expect("can have zero elements")
        {
            Some(mut existing_opouts) => {
                existing_opouts.push(opout)?;
                let _ = self.terminal_index.insert(seal, existing_opouts);
            }
            None => {
                self.terminal_index.insert(seal, medium_bset![opout])?;
            }
        }
        Ok(())
    }
}
