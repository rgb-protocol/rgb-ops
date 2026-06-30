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
use std::cmp::min_by_key;
use std::collections::{btree_map, hash_map, BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fmt::Debug;
use std::num::NonZeroU32;
use std::sync::Mutex;

use aluvm::library::{Lib, LibId};
use amplify::confinement::Confined;
use amplify::ByteArray;
use rgb::bitcoin::block::Header;
use rgb::bitcoin::{OutPoint as Outpoint, Transaction as Tx, Txid};
use rgb::commit_verify::mpc::{self, MerkleBlock};
use rgb::commit_verify::Conceal;
use rgb::dbc::{Anchor, Proof};
use rgb::validation::{
    OpoutsDagData, OpoutsDagInfo, ResolveWitness, SchemaDefinition, SchemaRules, Scripts, SpvProof,
    TypeLibs, UnsafeHistoryMap, WitnessOrdProvider, WitnessResolverError, WitnessStatus,
};
use rgb::vm::WitnessOrd;
use rgb::{
    Assign, AssignmentType, Assignments, BundleId, ChainNet, ContractId, ExposedSeal, ExposedState,
    Genesis, GlobalState, GraphSeal, Identity, KnownTransition, Layer1, OpId, Operation, Opout,
    OutputSeal, Schema, SchemaId, SecretSeal, Transition, TransitionBundle, TransitionType,
    TypedAssigns,
};
use strict_encoding::StrictDecode;
use strict_types::FieldName;

use super::codec::enc as enc_state;
use super::error::{ConsignError, DataError, FasciaError, Inconsistency, StockError};
use super::reader::{decode_allocated, load_output_assignments, resolved_at_outpoint};
use super::{
    AllocKind, AllocSeal, AllocationFilter, AllocationWrite, ContractStateSnapshot,
    GlobalStateWrite, RgbStore, TxBegin, TxMode, Visibility,
};
use crate::containers::{
    BuilderSeal, Consignment, ConsignmentExt, ConsignmentVer, Contract, Fascia, SealWitness,
    TerminalSeals, Transfer, ValidConsignment, ValidContract, ValidTransfer, WitnessBundle,
};
use crate::contract::{
    AllocatedState, ContractBuilder, ContractData, ContractStateRead, FilteredContractState,
    IssuerWrapper, KnownState, LinkError, LinkableIssuerWrapper, LinkableSchemaWrapper,
    OutputAssignment, SchemaWrapper, TransitionBuilder,
};
use crate::indexers::ResolveSpvProof;
use crate::info::{ContractInfo, SchemaInfo};
use crate::MergeReveal;

pub type ContractAssignments = HashMap<OutputSeal, HashMap<Opout, AllocatedState>>;

type SortedBundlesWithDag = (Vec<WitnessBundle>, Option<OpoutsDagData>);

type ConsignmentWithOptDag<const TRANSFER: bool> = (Consignment<TRANSFER>, Option<OpoutsDagData>);

/// What the composition helpers hand back: the consignment, its DAG when one
/// was asked for, and the SPV proofs retrieved on the way.
type ComposedConsignment<const TRANSFER: bool> =
    (Consignment<TRANSFER>, Option<OpoutsDagData>, RetrievedSpvProofs);

/// Consignment, its operations DAG and the retrieved SPV proofs
pub type ConsignmentWithDag<const TRANSFER: bool> =
    (Consignment<TRANSFER>, OpoutsDagData, RetrievedSpvProofs);

/// The SPV proofs a composition retrieved from its resolver, by witness id.
///
/// Only the ones the store was missing: what it already held is attached to the
/// consignment without being fetched, and so is not repeated here. Empty when no
/// resolver was given, or when nothing had to be fetched. Pass it to
/// [`Stock::store_spv_proofs`] to keep what was retrieved.
pub type RetrievedSpvProofs = BTreeMap<Txid, SpvProof>;

/// What a consignment must include and how it is composed, threaded through the
/// composition helpers of [`Stock`].
struct ConsignParams<'a> {
    /// Seals whose state must be included and reported as terminals.
    outputs: &'a [OutputSeal],
    /// Blinded seals whose state must be included and reported as terminals.
    secret_seals: &'a [SecretSeal],
    /// If set, restrict the consignment to bundles anchored by this witness and
    /// carry them under it: a bundle anchored under several transactions is
    /// otherwise carried under the one ranking first, which need not be the one
    /// the consignment is about.
    ///
    /// Unused when composing from a [`Fascia`], which carries its own witness.
    witness_id: Option<Txid>,
    /// See [`Stock::transfer`].
    spv_resolver: Option<&'a dyn ResolveSpvProof>,
    /// Whether to also build the operations DAG.
    build_opouts_dag: bool,
}

/// Outcome of [`Stock::update_witnesses`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct UpdateRes {
    /// How many witnesses were re-resolved against the chain.
    pub succeeded: usize,
    /// The witnesses the resolver could not answer for, with error message. Their
    /// stored ord is left as it was; a storage failure, by contrast, aborts the
    /// whole update rather than being reported here.
    pub failed: HashMap<Txid, String>,
}

/// Outcome of checking a witness against the SPV proof stored for it.
enum SpvCheck {
    /// The proof verifies against the block at its height in the best chain.
    Confirmed(WitnessStatus),
    /// There is no proof: nothing to check.
    Absent,
    /// There is a proof, but the resolver serves no block headers to check it against.
    Uncheckable,
    /// The proof does not verify: a reorg replaced the block it points at.
    Refuted,
}

/// The update to apply to a witness ord: what re-resolving the witness against
/// the chain found, as computed outside the store transaction which then
/// applies it. [`WitnessOrdChange`] is what applying it means.
struct WitnessOrdUpdate {
    /// The freshly resolved ord.
    ord: WitnessOrd,
    /// Whether the SPV proof stored for the witness failed to verify, so that
    /// it has to be dropped.
    proof_refuted: bool,
}

/// Outcome of applying a [`WitnessOrdUpdate`] to the ord of a witness.
enum WitnessOrdChange {
    /// The ord did not change, or changed without crossing validity.
    Kept,
    /// The witness became valid; carries the bundles it is known to witness.
    BecameValid(BTreeSet<BundleId>),
    /// The witness became invalid; carries the bundles it is known to witness.
    BecameInvalid(BTreeSet<BundleId>),
}

/// An open store transaction, rolled back unless it is
/// [committed](Self::commit).
///
/// It holds the stock for the length of the unit of work and hands it back out
/// through [`stock`](Self::stock), so that every way out of the transaction -
/// an early `?`, a failed commit, or a panic unwinding through it - goes
/// through the same rollback, and none of them can leave a transaction open on
/// a store which will go on being used.
struct StoreTransaction<'a, S: RgbStore> {
    stock: &'a mut Stock<S>,
    committed: bool,
}

impl<'a, S: RgbStore> StoreTransaction<'a, S> {
    /// Opens a transaction over `stock`, or reports `None` if the store already
    /// had one open - a nesting the caller must refuse, since the transaction
    /// belongs to whoever opened it.
    ///
    /// Finding out and opening is the store's one indivisible step, so two
    /// threads reaching the same store cannot both come away owning it.
    fn open(stock: &'a mut Stock<S>) -> Result<Option<Self>, S::Error> {
        match stock.store.begin(TxMode::Write)? {
            TxBegin::AlreadyOpen => Ok(None),
            TxBegin::Opened => Ok(Some(Self {
                stock,
                committed: false,
            })),
        }
    }

    /// The stock the transaction runs over.
    fn stock(&mut self) -> &mut Stock<S> { self.stock }

    /// Commits, leaving the drop nothing to roll back. A failed commit is left
    /// to the drop, so that it cannot stay open either.
    fn commit(mut self) -> Result<(), S::Error> {
        self.stock.store.commit()?;
        self.committed = true;
        Ok(())
    }
}

impl<S: RgbStore> Drop for StoreTransaction<'_, S> {
    fn drop(&mut self) {
        if !self.committed {
            self.stock.store.rollback();
        }
    }
}

/// An open read transaction, rolled back when it goes out of scope.
///
/// Reads are transactional so that a read API making several store calls sees
/// one state throughout, rather than a different one per call. It is only ever
/// rolled back: a read writes nothing, so there is nothing to commit, and
/// ending it the same way on every path - an early `?`, a panic - keeps it from
/// outliving the call that opened it.
///
/// A read reached from inside a unit of work joins that transaction instead of
/// opening its own, and then owns nothing: `owned` is what tells the two apart.
pub(super) struct ReadTransaction<'a, S: RgbStore> {
    store: &'a S,
    owned: bool,
}

impl<'a, S: RgbStore> ReadTransaction<'a, S> {
    pub(super) fn open(store: &'a S) -> Result<Self, S::Error> {
        let owned = store.begin(TxMode::Read)? == TxBegin::Opened;
        Ok(Self { store, owned })
    }
}

impl<S: RgbStore> Drop for ReadTransaction<'_, S> {
    fn drop(&mut self) {
        if self.owned {
            self.store.rollback();
        }
    }
}

#[derive(Debug)]
pub struct Stock<S: RgbStore> {
    store: S,
    /// Verified rules by schema id; see [`Stock::schema_rules`].
    ///
    /// Schema ids are content-addressed, so later imports cannot change a
    /// cached entry. Filled only after [`Stock::import_schema_definition`]
    /// commits, so a rolled-back import leaves nothing here.
    rules: Mutex<HashMap<SchemaId, SchemaRules>>,
}

impl<S: RgbStore + Default> Default for Stock<S> {
    fn default() -> Self { Self::with(default!()) }
}

impl<S: RgbStore> Stock<S> {
    /// Constructs a stock over the given store.
    pub fn with(store: S) -> Self {
        Stock {
            store,
            rules: default!(),
        }
    }

    /// Direct access to the underlying data store.
    #[doc(hidden)]
    pub fn as_store(&self) -> &S { &self.store }

    /// Iterates over every known schema info.
    pub fn schemata(&self) -> impl Iterator<Item = Result<SchemaInfo, StockError<S>>> + '_ {
        self.store
            .schemata()
            .map(|r| r.map_err(StockError::Store).map(|s| SchemaInfo::with(&s)))
    }

    /// Returns a stored schema, reporting its absence as a storage inconsistency.
    pub fn schema(&self, schema_id: SchemaId) -> Result<Schema, StockError<S>> {
        self.load_schema(schema_id)
    }

    /// Loads a schema which is required to be already imported, reporting its
    /// absence as [`StockError::SchemaNotImported`] rather than as a storage
    /// inconsistency: a missing schema means the user has not imported the
    /// schema definition, not that the storage is corrupted.
    fn load_imported_schema(&self, schema_id: SchemaId) -> Result<Schema, StockError<S>> {
        self.store
            .schema(schema_id)
            .map_err(StockError::Store)?
            .ok_or(StockError::SchemaNotImported(schema_id))
    }

    /// Iterates over every known contract info.
    pub fn contracts(&self) -> impl Iterator<Item = Result<ContractInfo, StockError<S>>> + '_ {
        self.geneses().map(|r| r.map(|g| ContractInfo::with(&g)))
    }

    /// Iterates over ids of all contract assigning state to the provided set of
    /// output seals.
    pub fn contracts_assigning(
        &self,
        outputs: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<impl Iterator<Item = ContractId>, StockError<S>> {
        let outputs = outputs
            .into_iter()
            .map(|o| o.into())
            .collect::<BTreeSet<_>>();
        Ok(self
            .store
            .contracts_assigning(&outputs)
            .map_err(StockError::Store)?
            .into_iter())
    }

    /// Returns the summary for a known contract.
    pub fn contract_info(&self, contract_id: ContractId) -> Result<ContractInfo, StockError<S>> {
        Ok(ContractInfo::with(&self.genesis(contract_id)?))
    }

    /// Returns a state reader for a known contract.
    pub fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<ContractStateSnapshot, StockError<S>> {
        self.read_contract_state(contract_id)
    }

    /// Returns a schema wrapper for a known contract.
    pub fn contract_wrapper<C: IssuerWrapper>(
        &self,
        contract_id: ContractId,
    ) -> Result<C::Wrapper<ContractStateSnapshot>, StockError<S>> {
        self.schema_wrapper::<C::Wrapper<_>>(contract_id)
    }

    fn schema_wrapper<C: SchemaWrapper<ContractStateSnapshot>>(
        &self,
        contract_id: ContractId,
    ) -> Result<C, StockError<S>> {
        let contract_data = self.contract_data(contract_id)?;
        Ok(C::with(contract_data))
    }

    /// Returns the contract data for the given contract ID
    pub fn contract_data(
        &self,
        contract_id: ContractId,
    ) -> Result<ContractData<ContractStateSnapshot>, StockError<S>> {
        let _read_tx = ReadTransaction::open(&self.store).map_err(StockError::Store)?;
        let state = self.read_contract_state(contract_id)?;
        let rules = self.schema_rules(state.schema_id())?;
        let info = self.contract_info(contract_id)?;

        Ok(ContractData { state, rules, info })
    }

    /// The contract's allocations matching `filter`, each with the witness it
    /// is reported under.
    pub fn allocations<State: StrictDecode + KnownState>(
        &self,
        contract_id: ContractId,
        filter: AllocationFilter<'_>,
    ) -> Result<Vec<OutputAssignment<State>>, StockError<S>> {
        let _read_tx = ReadTransaction::open(&self.store).map_err(StockError::Store)?;
        Ok(load_output_assignments(&self.store, contract_id, filter)?)
    }

    /// Returns the contract data of a validated consignment, reading the rules
    /// it was issued under from the store.
    ///
    /// The schema must have been imported (see
    /// [`Stock::import_schema_definition`]): a consignment carries neither the
    /// schema nor the type system, only the schema id its genesis commits to.
    pub fn consignment_data<const TRANSFER: bool>(
        &self,
        consignment: &ValidConsignment<TRANSFER>,
    ) -> Result<ContractData<FilteredContractState>, StockError<S>> {
        let rules = self.schema_rules(consignment.genesis.schema_id)?;
        Ok(consignment.build_contract_data(&rules))
    }

    /// Returns the contract's assignments allocated on the given outpoints.
    ///
    /// A seal on the witness transaction is found at the outpoint of every
    /// witness of its bundle that is not archived, so an assignment may be
    /// reported under two of the outpoints asked for at once.
    pub fn contract_assignments_for(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<ContractAssignments, StockError<S>> {
        let outputs: BTreeSet<Outpoint> = outpoints.into_iter().map(|o| o.into()).collect();

        // one query with the outpoint filter pushed into it: a question this
        // narrow is not worth reading a contract's whole state to answer, and
        // one query needs no read transaction to be of one DB state
        let rows = self
            .store
            .allocations(contract_id, AllocationFilter::all(Visibility::Valid).at(&outputs))
            .map_err(StockError::Store)?;

        let mut res =
            HashMap::<OutputSeal, HashMap<Opout, AllocatedState>>::with_capacity(outputs.len());
        for row in rows {
            let state = decode_allocated(&row)?;
            res.entry(resolved_at_outpoint(&row))
                .or_default()
                .insert(row.opout, state);
        }

        Ok(res)
    }

    /// Returns the assignments allocated on the given outpoints, grouped by the
    /// contract which assigns them.
    ///
    /// Answers the same question as [`Self::contracts_assigning`] followed by a
    /// [`Self::contract_assignments_for`] per contract found, with a single
    /// store query instead of one per contract over the same rows. Prefer it
    /// whenever the assignments themselves are wanted, and not just the set of
    /// contract ids.
    ///
    /// A contract whose allocations at these outpoints are all invalid is
    /// absent from the map rather than mapped to an empty set: it assigns no
    /// visible state there, which is what the per-contract path reports too.
    pub fn assignments_by_contract(
        &self,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeMap<ContractId, ContractAssignments>, StockError<S>> {
        let outputs: BTreeSet<Outpoint> = outpoints.into_iter().map(|o| o.into()).collect();

        // one query over every contract, filtered as it is read: no read
        // transaction to pin, since nothing is compared across two of them
        let rows = self
            .store
            .all_allocations_at_outpoints(&outputs, Visibility::Valid)
            .map_err(StockError::Store)?;

        let mut res = BTreeMap::<ContractId, ContractAssignments>::new();
        for (contract_id, row) in rows {
            let state = decode_allocated(&row)?;
            res.entry(contract_id)
                .or_default()
                .entry(resolved_at_outpoint(&row))
                .or_default()
                .insert(row.opout, state);
        }

        Ok(res)
    }

    /// Starts a contract issuance with a known schema.
    pub fn contract_builder(
        &self,
        issuer: impl Into<Identity>,
        schema_id: SchemaId,
        chain_net: ChainNet,
    ) -> Result<ContractBuilder, StockError<S>> {
        let rules = self.schema_rules(schema_id)?;
        Ok(ContractBuilder::with(issuer.into(), rules, chain_net))
    }

    /// Starts a state transition of the named type on a known contract.
    pub fn transition_builder(
        &self,
        contract_id: ContractId,
        transition_name: impl Into<FieldName>,
    ) -> Result<TransitionBuilder, StockError<S>> {
        let rules = self.contract_schema_rules(contract_id)?;
        let (schema, types, _) = rules.into_parts();
        let transition_type = schema.transition_type(transition_name);
        Ok(TransitionBuilder::with(contract_id, schema, transition_type, types))
    }

    /// Starts a state transition of the given type on a known contract.
    pub fn transition_builder_raw(
        &self,
        contract_id: ContractId,
        transition_type: TransitionType,
    ) -> Result<TransitionBuilder, StockError<S>> {
        let rules = self.contract_schema_rules(contract_id)?;
        let (schema, types, _) = rules.into_parts();
        Ok(TransitionBuilder::with(contract_id, schema, transition_type, types))
    }

    /// The verified [`SchemaRules`] for `schema_id`.
    ///
    /// The store keeps a schema definition decomposed, so the first call
    /// reassembles it and puts it through [`SchemaDefinition::verify`] - the
    /// same check a definition crossing a trust boundary gets, deriving the type
    /// system from the stored type libraries rather than trusting one the store
    /// handed over. The verified rules are then kept in memory, so what the
    /// callers on the state paths repeat is a map lookup and not that
    /// derivation.
    pub fn schema_rules(&self, schema_id: SchemaId) -> Result<SchemaRules, StockError<S>> {
        if let Some(rules) = self.cached_rules(schema_id) {
            return Ok(rules);
        }
        let _read_tx = ReadTransaction::open(&self.store).map_err(StockError::Store)?;
        let schema = self.load_schema(schema_id)?;
        self.rules_of(schema)
    }

    /// The definition a schema was imported from, put back together from the
    /// store.
    ///
    /// The schema, its type libraries and its AluVM libraries are each stored
    /// whole, so what comes back is what went in, and a stock can hand a schema
    /// on to another stock without the file it was imported from. Importing the
    /// same schema twice changes nothing: a definition which verifies carries
    /// exactly the libraries its schema needs, so there is only ever one set of
    /// them to store.
    pub fn export_schema_definition(
        &self,
        schema_id: SchemaId,
    ) -> Result<SchemaDefinition, StockError<S>> {
        let _read_tx = ReadTransaction::open(&self.store).map_err(StockError::Store)?;
        let schema = self.load_imported_schema(schema_id)?;
        self.assemble_schema_definition(schema)
    }

    /// Exports a contract consignment (genesis only).
    pub fn export_contract(
        &self,
        contract_id: ContractId,
    ) -> Result<Contract, StockError<S, ConsignError>> {
        self.consign::<false>(contract_id, [], &ConsignParams {
            outputs: &[],
            secret_seals: &[],
            witness_id: None,
            spv_resolver: None,
            build_opouts_dag: false,
        })
        // no resolver is passed, so nothing is ever retrieved to hand back
        .map(|(c, ..)| c)
    }

    /// Compose a transfer consignment.
    ///
    /// `spv_resolver` controls the SPV proofs the consignment carries, letting the
    /// receiver verify the witnesses from block headers alone. With `None` only the proofs
    /// already in the store are used; with `Some` the missing ones are retrieved on the
    /// spot, so that a wallet need not keep a proof stored for every witness it knows.
    ///
    /// Retrieval is best-effort: a witness whose proof cannot be obtained simply travels
    /// without one, which is always legal. In particular the witness of the transfer being
    /// composed has no proof, since the consignment is handed over before it is broadcast.
    ///
    /// What is retrieved is attached to the consignment and not stored, so composing does
    /// not need `&mut self` and several threads may compose at once. It is also returned
    /// as [`RetrievedSpvProofs`], so a wallet which does want those proofs kept passes
    /// them to [`Stock::store_spv_proofs`] without asking the resolver again.
    pub fn transfer(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        opids: impl IntoIterator<Item = OpId>,
        witness_id: Option<Txid>,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<(Transfer, RetrievedSpvProofs), StockError<S, ConsignError>> {
        self.consign(contract_id, opids, &ConsignParams {
            outputs: outputs.as_ref(),
            secret_seals: secret_seals.as_ref(),
            witness_id,
            spv_resolver,
            build_opouts_dag: false,
        })
        .map(|(c, _, p)| (c, p))
    }

    /// See [`Stock::transfer`] for `spv_resolver`.
    pub fn transfer_with_dag(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        opids: impl IntoIterator<Item = OpId>,
        witness_id: Option<Txid>,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<ConsignmentWithDag<true>, StockError<S, ConsignError>> {
        self.consign(contract_id, opids, &ConsignParams {
            outputs: outputs.as_ref(),
            secret_seals: secret_seals.as_ref(),
            witness_id,
            spv_resolver,
            build_opouts_dag: true,
        })
        .map(|(c, d, p)| (c, d.expect("build_opouts_dag=true"), p))
    }

    fn sort_bundles(
        &self,
        bundles: BTreeMap<BundleId, (WitnessBundle, u32)>,
        contract_id: ContractId,
        build_opouts_dag: bool,
        genesis: &Genesis,
    ) -> Result<SortedBundlesWithDag, StockError<S, ConsignError>> {
        let mut dag_info = None;
        if build_opouts_dag {
            dag_info = Some(OpoutsDagInfo::new());
        }
        if let Some(ref mut dag_info) = dag_info {
            dag_info.register_outputs(genesis, &genesis.id());
        }

        let bundles_len = bundles.len();
        if bundles_len <= 1 {
            let bundles = bundles.into_values().map(|(b, _)| b).collect::<Vec<_>>();
            if let Some(ref mut dag_info) = dag_info {
                dag_info.build_dag(
                    &bundles
                        .iter()
                        .flat_map(|wb| wb.bundle.known_transitions.iter())
                        .collect::<Vec<_>>(),
                );
            }
            return Ok((bundles, dag_info.map(|d| d.to_opouts_dag_data())));
        }

        // Pre-sort by witness height for efficiency
        let mut bundles_with_height = bundles.into_iter().collect::<Vec<_>>();
        bundles_with_height.sort_by_key(|(_, (_, num))| *num);

        // Dependency violation detection
        let mut needs_reordering = false;
        let bundle_positions = bundles_with_height
            .iter()
            .enumerate()
            .map(|(i, (bundle_id, (_, _)))| (*bundle_id, i))
            .collect::<HashMap<_, _>>();
        'outer: for (i, (_, (witness_bundle, _))) in bundles_with_height.iter().enumerate() {
            for KnownTransition { transition, opid } in &witness_bundle.bundle.known_transitions {
                if let Some(ref mut dag_info) = dag_info {
                    dag_info.register_outputs(transition, opid);
                }
                for input in &transition.inputs {
                    if let Some(ref mut dag_info) = dag_info {
                        dag_info.connect_input_to_outputs_by_opid(input, opid);
                    }
                    if input.op != contract_id {
                        let input_bundle_id = self.bundle_id_for_op(input.op)?;
                        // ignore missing input bundles (e.g. can happen in case of replace)
                        if let Some(&input_pos) = bundle_positions.get(&input_bundle_id) {
                            if input_pos > i {
                                needs_reordering = true;
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }
        if !needs_reordering {
            let bundles = bundles_with_height
                .into_iter()
                .map(|(_, (wb, _))| wb)
                .collect::<Vec<_>>();
            return Ok((bundles, dag_info.map(|d| d.to_opouts_dag_data())));
        }

        // Topological sort
        let mut known_bundle_dependencies: HashMap<BundleId, HashSet<BundleId>> =
            HashMap::with_capacity(bundles_len);
        for (bundle_id, (witness_bundle, _)) in &bundles_with_height {
            for KnownTransition { transition, opid } in &witness_bundle.bundle.known_transitions {
                if let Some(ref mut dag_info) = dag_info {
                    dag_info.register_outputs(transition, opid);
                }
                for input in &transition.inputs {
                    if let Some(ref mut dag_info) = dag_info {
                        dag_info.connect_input_to_outputs_by_opid(input, opid);
                    }
                    if input.op != contract_id {
                        let input_bundle_id = self.bundle_id_for_op(input.op)?;
                        if bundle_positions.contains_key(&input_bundle_id)
                            && input_bundle_id != *bundle_id
                        {
                            known_bundle_dependencies
                                .entry(*bundle_id)
                                .or_default()
                                .insert(input_bundle_id);
                        }
                    }
                }
            }
        }
        let mut sorted_bundles: Vec<WitnessBundle> = Vec::with_capacity(bundles_len);
        let mut remaining = bundles_with_height
            .into_iter()
            .map(|(id, (wb, _))| (id, wb))
            .collect::<Vec<_>>();
        while !remaining.is_empty() {
            let processed_ids = sorted_bundles
                .iter()
                .map(|wb| wb.bundle.bundle_id())
                .collect::<HashSet<_>>();
            let mut found = false;
            let mut i = 0;
            while i < remaining.len() {
                let (bundle_id, _) = &remaining[i];
                let dependencies = known_bundle_dependencies
                    .get(bundle_id)
                    .cloned()
                    .unwrap_or_default();
                if dependencies.is_subset(&processed_ids) {
                    let (_, witness_bundle) = remaining.remove(i);
                    sorted_bundles.push(witness_bundle);
                    found = true;
                    break;
                }
                i += 1;
            }
            if !found {
                return Err(StockError::BundlesInconsistency);
            }
        }
        Ok((sorted_bundles, dag_info.map(|d| d.to_opouts_dag_data())))
    }

    fn consign<const TRANSFER: bool>(
        &self,
        contract_id: ContractId,
        opids: impl IntoIterator<Item = OpId>,
        params: &ConsignParams,
    ) -> Result<ComposedConsignment<TRANSFER>, StockError<S, ConsignError>> {
        let mut pending_spv = bset![];
        let (mut consignment, dag) = {
            let _read_tx =
                ReadTransaction::open(&self.store).map_err(StockError::<S, ConsignError>::Store)?;
            // Collect initial set of opids to include
            let mut opids = opids.into_iter().collect::<HashSet<_>>();
            let by_output = self.opouts_by_outputs(contract_id, params.outputs.iter().copied())?;
            // an output the contract assigns nothing to is a caller error here,
            // though not to the lookup: it asks for a terminal over state which
            // is not there, and the consignment would come out silently missing
            // it rather than wrong
            if let Some(missing) = params
                .outputs
                .iter()
                .map(|o| o.to_outpoint())
                .find(|o| !by_output.contains_key(o))
            {
                return Err(Inconsistency::OutpointUnknown(missing, contract_id).into());
            }
            opids.extend(
                by_output
                    .into_values()
                    .flatten()
                    .chain(
                        self.opouts_by_secrets(contract_id, params.secret_seals.iter().copied())?,
                    )
                    .map(|opout| opout.op),
            );

            self.consign_operations(contract_id, opids, params, &mut pending_spv)?
        };
        let retrieved = Self::attach_spv_proofs(&mut consignment, pending_spv, params.spv_resolver);
        Ok((consignment, dag, retrieved))
    }

    /// Attaches to the composed consignment the SPV proofs the store had none
    /// of, retrieving them from `spv_resolver`.
    ///
    /// Deliberately outside the read transaction composition runs in: this is
    /// the one step that talks to the resolver, and holding the store's read
    /// lock across that round-trip would make every writer wait on the network,
    /// and then fail, contention being reported rather than retried. It reads
    /// nothing from the store, so there is nothing left for the transaction to
    /// keep consistent.
    ///
    /// Best-effort: a witness whose proof cannot be retrieved is left without
    /// one, exactly as one which was never mined.
    ///
    /// Returns what it fetched, so a caller which wants those proofs kept can
    /// store exactly them - see [`Stock::store_spv_proofs`] - rather than
    /// walking the consignment and re-storing proofs which came out of the
    /// store to begin with.
    fn attach_spv_proofs<const TRANSFER: bool>(
        consignment: &mut Consignment<TRANSFER>,
        pending_spv: BTreeSet<Txid>,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> RetrievedSpvProofs {
        let Some(resolver) = spv_resolver else {
            return none!();
        };
        let proofs = pending_spv
            .into_iter()
            .filter_map(|id| Some((id, resolver.resolve_spv_proof(id).ok()?)))
            .collect::<RetrievedSpvProofs>();
        if proofs.is_empty() {
            return proofs;
        }
        for witness_bundle in consignment.bundles.iter_mut() {
            if witness_bundle.spv_proof.is_none() {
                witness_bundle.spv_proof = proofs.get(&witness_bundle.witness_id()).cloned();
            }
        }
        proofs
    }

    fn consign_operations<const TRANSFER: bool>(
        &self,
        contract_id: ContractId,
        opids: impl IntoIterator<Item = OpId>,
        params: &ConsignParams,
        pending_spv: &mut BTreeSet<Txid>,
    ) -> Result<ConsignmentWithOptDag<TRANSFER>, StockError<S, ConsignError>> {
        let ConsignParams {
            outputs,
            secret_seals,
            witness_id,
            ..
        } = params;
        // 1.3. Collect all state transitions assigning state to the provided outpoints
        let mut bundles = BTreeMap::<BundleId, (WitnessBundle, u32)>::new();
        // witness selected for each bundle, cached since several opids may share a bundle
        let mut bundle_witnesses = HashMap::<BundleId, (Txid, WitnessOrd)>::new();
        let mut parent_opids = Vec::<OpId>::new();
        let mut terminal_seals: BTreeMap<BundleId, BTreeSet<BuilderSeal<GraphSeal>>> =
            BTreeMap::new();
        for opid in opids {
            if opid == contract_id {
                continue; // we skip genesis since it will be present anywhere
            }

            let transition = self.transition(opid)?;

            let bundle_id = self.bundle_id_for_op(transition.id())?;

            let (witness_ids, bundle_contract_id) = self.bundle_info(bundle_id)?;
            // skip bundles not anchored by the terminals witness
            if witness_id.is_some_and(|wid| !witness_ids.contains(&wid)) {
                continue;
            }
            let bundle_witness = match bundle_witnesses.get(&bundle_id) {
                Some(&witness) => witness,
                None => {
                    // under the witness the caller named, when it named one:
                    // the first-ranked one is the same whichever of the
                    // bundle's witnesses the consignment is about
                    let candidates = match witness_id {
                        Some(wid) => bset![*wid],
                        None => witness_ids,
                    };
                    let witness = self.select_valid_witness(candidates)?;
                    bundle_witnesses.insert(bundle_id, witness);
                    witness
                }
            };
            let (bundle_witness_id, _) = bundle_witness;

            parent_opids.extend(transition.inputs().iter().map(|input| input.op));

            // 1.4. Collect terminal seals for this bundle to add to the consignment terminals.
            for typed_assignments in transition.assignments.values() {
                for index in 0..typed_assignments.len_u16() {
                    let seal = *typed_assignments.seal_at(index).expect("cycling indexes");
                    let include_terminal = match seal {
                        BuilderSeal::Revealed(revealed_seal) => outputs
                            .contains(&revealed_seal.to_output_seal_or_default(bundle_witness_id)),
                        BuilderSeal::Concealed(secret_seal) => secret_seals.contains(&secret_seal),
                    };
                    if include_terminal {
                        terminal_seals.entry(bundle_id).or_default().insert(seal);
                    }
                }
            }

            if let Some((wbundle, _)) = bundles.get_mut(&bundle_id) {
                wbundle.bundle.reveal_transition(transition)?;
            } else {
                bundles.insert(
                    bundle_id,
                    self.witness_bundle(
                        bundle_id,
                        opid,
                        bundle_contract_id,
                        bundle_witness,
                        pending_spv,
                    )?,
                );
            };
        }
        self.consign_bundles(
            contract_id,
            bundles,
            parent_opids,
            terminal_seals,
            params,
            pending_spv,
        )
    }

    fn consign_bundles<const TRANSFER: bool>(
        &self,
        contract_id: ContractId,
        mut bundles: BTreeMap<BundleId, (WitnessBundle, u32)>,
        mut parent_opids: Vec<OpId>,
        terminal_seals: BTreeMap<BundleId, BTreeSet<BuilderSeal<GraphSeal>>>,
        params: &ConsignParams,
        pending_spv: &mut BTreeSet<Txid>,
    ) -> Result<ConsignmentWithOptDag<TRANSFER>, StockError<S, ConsignError>> {
        // 2. Collect all state transitions between terminals and genesis
        let mut seen_ids = HashSet::new();
        while let Some(id) = parent_opids.pop() {
            if id == contract_id {
                continue; // we skip genesis since it will be present anywhere
            }
            if !seen_ids.insert(id) {
                continue; // we skip seen IDs to avoid re-processing duplicates
            }
            let transition = self.transition(id)?;
            parent_opids.extend(transition.inputs().iter().map(|input| input.op));
            let bundle_id = self.bundle_id_for_op(transition.id())?;
            if let Some((wbundle, _)) = bundles.get_mut(&bundle_id) {
                wbundle.bundle.reveal_transition(transition)?;
            } else {
                let (witness_ids, bundle_contract_id) = self.bundle_info(bundle_id)?;
                let bundle_witness = self.select_valid_witness(witness_ids)?;
                bundles.insert(
                    bundle_id,
                    self.witness_bundle(
                        bundle_id,
                        id,
                        bundle_contract_id,
                        bundle_witness,
                        pending_spv,
                    )?,
                );
            };
        }

        let genesis = self.genesis(contract_id)?.clone();

        // fail early: a consignment can only be produced for a schema this
        // store knows, since the consignment itself carries just its id
        self.load_imported_schema(genesis.schema_id)?;

        let (sorted_bundles, dag) =
            self.sort_bundles(bundles, contract_id, params.build_opouts_dag, &genesis)?;

        let bundles =
            Confined::try_from_iter(sorted_bundles).map_err(|_| ConsignError::TooManyBundles)?;
        let terminals = Confined::try_from(
            terminal_seals
                .into_iter()
                .map(|(bundle_id, seals)| {
                    Confined::try_from_iter(seals)
                        .map(|confined| (bundle_id, TerminalSeals::from(confined)))
                        .map_err(|_| ConsignError::TooManyTerminalSeals)
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?,
        )
        .map_err(|_| ConsignError::TooManyTerminalBundles)?;

        // TODO: Conceal everything we do not need

        let consignment = Consignment {
            version: ConsignmentVer::V1,
            transfer: TRANSFER,

            genesis,
            terminals,
            bundles,
        };

        Ok((consignment, dag))
    }

    /// See [`Stock::transfer`] for `spv_resolver`.
    pub fn transfer_from_fascia(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        opids: impl IntoIterator<Item = OpId>,
        fascia: &Fascia,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<(Consignment<true>, RetrievedSpvProofs), StockError<S, ConsignError>> {
        self.consign_from_fascia(contract_id, opids, fascia, &ConsignParams {
            outputs: outputs.as_ref(),
            secret_seals: secret_seals.as_ref(),
            witness_id: None,
            spv_resolver,
            build_opouts_dag: false,
        })
        .map(|(c, _, p)| (c, p))
    }

    /// See [`Stock::transfer`] for `spv_resolver`.
    pub fn transfer_from_fascia_with_dag(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        opids: impl IntoIterator<Item = OpId>,
        fascia: &Fascia,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<ConsignmentWithDag<true>, StockError<S, ConsignError>> {
        self.consign_from_fascia(contract_id, opids, fascia, &ConsignParams {
            outputs: outputs.as_ref(),
            secret_seals: secret_seals.as_ref(),
            witness_id: None,
            spv_resolver,
            build_opouts_dag: true,
        })
        .map(|(c, d, p)| (c, d.expect("build_opouts_dag=true"), p))
    }

    fn consign_from_fascia(
        &self,
        contract_id: ContractId,
        opids: impl IntoIterator<Item = OpId>,
        fascia: &Fascia,
        params: &ConsignParams,
    ) -> Result<ComposedConsignment<true>, StockError<S, ConsignError>> {
        let mut pending_spv = bset![];
        let (mut consignment, dag) =
            self.consign_from_fascia_in_tx(contract_id, opids, fascia, params, &mut pending_spv)?;
        let retrieved = Self::attach_spv_proofs(&mut consignment, pending_spv, params.spv_resolver);
        Ok((consignment, dag, retrieved))
    }

    /// The transactional half of [`Self::consign_from_fascia`]: everything which
    /// reads the store, and nothing which talks to the resolver.
    fn consign_from_fascia_in_tx(
        &self,
        contract_id: ContractId,
        opids: impl IntoIterator<Item = OpId>,
        fascia: &Fascia,
        params: &ConsignParams,
        pending_spv: &mut BTreeSet<Txid>,
    ) -> Result<ConsignmentWithOptDag<true>, StockError<S, ConsignError>> {
        let _read_tx =
            ReadTransaction::open(&self.store).map_err(StockError::<S, ConsignError>::Store)?;
        let mut contract_bundle = fascia
            .bundles()
            .get(&contract_id)
            .ok_or(ConsignError::UnrelatedContract(contract_id))?
            .clone();
        let bundle_id = contract_bundle.bundle_id();
        let all_bundle_opids = contract_bundle.input_map_opids();
        let bundle_revealed_opids = contract_bundle.known_transitions_opids();
        let opids = opids.into_iter().collect::<HashSet<_>>();
        let secret_seals = params.secret_seals.iter().cloned().collect::<BTreeSet<_>>();
        let outputs = params.outputs.iter().collect::<HashSet<_>>();
        let witness_id = fascia.witness_id();
        let is_requested_transition = |kt: &KnownTransition| {
            if opids.contains(&kt.opid) {
                return true; // 1. explicitly requested opids
            }
            for typed_assigns in kt.transition.assignments.values() {
                for index in 0..typed_assigns.len_u16() {
                    match typed_assigns
                        .revealed_seal_at(index)
                        .expect("cycling indexes")
                    {
                        Some(s) => {
                            if outputs.contains(&s.to_output_seal_or_default(witness_id)) {
                                return true; // 2. outputs
                            }
                        }
                        None => {
                            if secret_seals.contains(
                                &typed_assigns
                                    .confidential_seal_at(index)
                                    .expect("cycling indexes"),
                            ) {
                                return true; // 3. secret seals (blinded)
                            }
                        }
                    }
                }
            }
            false
        };
        // filter only required transitions in the bundle
        // process transitions in reverse order since children must appear after parents
        let mut required_opids = bset![];
        let mut rev_bundle_transitions = vec![];
        for known_transition in contract_bundle.known_transitions.into_iter().rev() {
            if required_opids.contains(&known_transition.opid)
                || is_requested_transition(&known_transition)
            {
                required_opids.remove(&known_transition.opid);
                required_opids.extend(known_transition.transition.inputs.iter().map(|o| o.op));
                rev_bundle_transitions.push(known_transition);
            }
        }
        if let Some(opid) = required_opids.intersection(&all_bundle_opids).next() {
            if let Some(opid) = required_opids.intersection(&bundle_revealed_opids).next() {
                return Err(ConsignError::ConcealedTransition(bundle_id, *opid).into());
            }
            return Err(ConsignError::UnorderedTransition(bundle_id, *opid).into());
        }
        rev_bundle_transitions.reverse();
        // the selection is a subset of an already-confined collection, so it can
        // only fail the lower bound: nothing in the bundle was requested, and a
        // bundle holding no transition cannot be consigned
        contract_bundle.known_transitions = Confined::try_from(rev_bundle_transitions)
            .map_err(|_| ConsignError::NoRequestedTransition(bundle_id))?;
        let SealWitness {
            tx: witness_tx,
            mpc_merkle_block,
            dbc_proof,
            spv_proof: _,
        } = fascia.seal_witness().clone();
        let anchor = Anchor::new(
            mpc_merkle_block
                .into_merkle_proof(contract_id.into())
                .map_err(|_| ConsignError::UnrelatedContract(contract_id))?,
            dbc_proof,
        );
        // Collect terminal seals actually present in the bundle: revealed for witness-vout
        // beneficiaries, concealed for blinded ones. Only matching seals are included so the
        // terminal-consistency check in the validator passes.
        let mut terminal_seals: BTreeSet<BuilderSeal<GraphSeal>> = BTreeSet::new();
        for kt in &contract_bundle.known_transitions {
            for typed_assigns in kt.transition.assignments.values() {
                for index in 0..typed_assigns.len_u16() {
                    match typed_assigns
                        .revealed_seal_at(index)
                        .expect("cycling indexes")
                    {
                        Some(seal) => {
                            if outputs.contains(&seal.to_output_seal_or_default(witness_id)) {
                                terminal_seals.insert(BuilderSeal::Revealed(seal));
                            }
                        }
                        None => {
                            let secret = typed_assigns
                                .confidential_seal_at(index)
                                .expect("cycling indexes");
                            if secret_seals.contains(&secret) {
                                terminal_seals.insert(BuilderSeal::Concealed(secret));
                            }
                        }
                    }
                }
            }
        }
        let terminal_seals = if !terminal_seals.is_empty() {
            bmap! {bundle_id => terminal_seals}
        } else {
            bmap! {}
        };
        self.consign_bundles(
            contract_id,
            bmap! {bundle_id => (WitnessBundle::with(witness_tx, anchor, contract_bundle), u32::MAX)},
            required_opids.into_iter().collect::<Vec<_>>(),
            terminal_seals,
            params,
            pending_spv,
        )
    }

    /// Runs `f` inside a single store transaction, committing its result on
    /// success and rolling back on any error, including a failure of the commit
    /// itself, so a transaction is never left open.
    ///
    /// The rollback is [`StoreTransaction`]'s to make: `f` returning an error
    /// and `f` panicking both unwind through the same drop, so a panic cannot
    /// leave a transaction open for the next unit of work to be committed with.
    ///
    /// Not re-entrant: `begin`/`commit` are not nestable, so `f` must not call
    /// another `store_transaction`. Every public mutator wraps exactly one of
    /// these; they are not composed.
    ///
    /// A nested call is refused with [`StockError::NestedTransaction`] instead
    /// of being let through: a store whose `begin`/`commit` are idempotent
    /// (as SQLite's are, keyed on its autocommit flag) cannot tell the inner
    /// call from the outer one, so the inner `commit` would commit the outer
    /// unit of work half-way and leave the rest of it running - and failing -
    /// outside any transaction.
    fn store_transaction<T, E: Error>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, StockError<S, E>>,
    ) -> Result<T, StockError<S, E>> {
        let Some(mut transaction) = StoreTransaction::open(self).map_err(StockError::Store)? else {
            return Err(StockError::NestedTransaction);
        };
        let val = f(transaction.stock())?;
        transaction.commit().map_err(StockError::Store)?;
        Ok(val)
    }

    /// Stores a [`SchemaDefinition`] (a schema together with the strict type
    /// libraries and AluVM libraries it needs) so contracts using that schema
    /// can be issued and validated.
    ///
    /// The definition is verified before being stored: its type libraries must
    /// derive exactly the semantic ids the schema commits to, and its AluVM
    /// libraries must match the ids the schema references. A definition
    /// imported once stays usable across runs - nothing has to be re-supplied
    /// from code.
    ///
    /// The store does not keep the definition whole: it stores the schema, the
    /// type libraries and the AluVM libraries separately, alongside those of
    /// every other imported schema. What was imported is still exactly
    /// recoverable - see [`Stock::export_schema_definition`] - because the
    /// definition's own type libraries are kept, and not just the type system
    /// derived from them.
    pub fn import_schema_definition(
        &mut self,
        schema_def: SchemaDefinition,
    ) -> Result<(), StockError<S>> {
        let schema_id = schema_def.schema_id();
        let rules = schema_def
            .verify()
            .map_err(|e| DataError::SchemaDef(schema_id, Box::new(e)))?;

        self.store_transaction(|s| {
            for lib in schema_def.libs.values() {
                s.store
                    .put_type_lib(schema_id, lib)
                    .map_err(StockError::Store)?;
            }
            for lib in schema_def.scripts.values() {
                s.store.put_aluvm_lib(lib).map_err(StockError::Store)?;
            }
            s.store
                .put_schema(&schema_def.schema)
                .map_err(StockError::Store)
        })?;

        // only now that the definition is committed: the rules just verified
        // are the ones a read would rebuild
        self.cache_rules(schema_id, &rules);
        Ok(())
    }

    /// Imports a validated contract genesis into the stock.
    pub fn import_contract<R: ResolveWitness>(
        &mut self,
        contract: ValidContract,
        resolver: R,
    ) -> Result<(), StockError<S>> {
        self.consume_consignment(contract, resolver)
    }

    /// Accepts a validated transfer consignment into the stock.
    pub fn accept_transfer<R: ResolveWitness>(
        &mut self,
        contract: ValidTransfer,
        resolver: R,
    ) -> Result<(), StockError<S>> {
        self.consume_consignment(contract, resolver)
    }

    /// Resolve a witness from its SPV proof instead of fetching the TX from an indexer.
    ///
    /// Returns [`SpvCheck::Absent`] when there is no proof and [`SpvCheck::Uncheckable`]
    /// when `resolver` cannot supply block headers, in both cases leaving the caller to
    /// fall back to [`ResolveWitness::resolve_witness`].
    ///
    /// The header is the one at the proof's height in the resolver's best chain, so a
    /// reorg which moved the witness elsewhere makes the proof fail to verify, reported as
    /// [`SpvCheck::Refuted`]. Falling back rather than reporting the witness as unresolved
    /// lets a client with a TX indexer pick up the new position; a client without one
    /// resolves it as unresolved anyway.
    ///
    /// Headers are memoized in `headers`, so that witnesses mined in the same block cost a
    /// single fetch over the whole pass.
    fn resolve_witness_spv<R: ResolveWitness>(
        resolver: &R,
        tx: &Tx,
        spv_proof: Option<&SpvProof>,
        layer1: Layer1,
        headers: &mut HashMap<NonZeroU32, Header>,
    ) -> Result<SpvCheck, WitnessResolverError> {
        let Some(proof) = spv_proof else {
            return Ok(SpvCheck::Absent);
        };
        let header = match headers.entry(proof.block_height) {
            hash_map::Entry::Occupied(e) => *e.get(),
            hash_map::Entry::Vacant(e) => match resolver.get_block_header(proof.block_height) {
                Ok(header) => *e.insert(header),
                Err(WitnessResolverError::NotSupported) => return Ok(SpvCheck::Uncheckable),
                Err(e) => return Err(e),
            },
        };
        let pos = match proof.verified_pos(tx.compute_txid(), &header, layer1) {
            Err(_) => return Ok(SpvCheck::Refuted),
            Ok(pos) => pos.ok_or(WitnessResolverError::InvalidResolverData)?,
        };
        Ok(SpvCheck::Confirmed(WitnessStatus::Resolved(tx.clone(), WitnessOrd::Mined(pos))))
    }

    /// Consumes a validated consignment.
    ///
    /// The consignment witnesses are re-resolved before consuming, since
    /// their ords may have changed after the validation, e.g. if a reorg
    /// happened in the meantime. If that leaves a consignment bundle without
    /// any valid witness, the consignment is NOT consumed and
    /// [`StockError::AbsentValidWitness`] is returned; in that case, as a
    /// side effect, the fresh ords of the already-known witnesses are stored
    /// and the known operations of the bundles left without a valid witness
    /// are set as invalid, together with all their descendants.
    fn consume_consignment<R: ResolveWitness, const TRANSFER: bool>(
        &mut self,
        consignment: ValidConsignment<TRANSFER>,
        resolver: R,
    ) -> Result<(), StockError<S>> {
        let consignment = consignment.into_consignment();

        // one read-only pass over the bundles: computing each one's ids and
        // resolving its witness with accept-time resolutions, which may differ
        // from the ones seen at validation time if a reorg happened in the
        // meantime. Witnesses carrying a still-valid SPV proof are resolved
        // from it, so that a client with no access to a TX indexer can consume
        // the consignment it has just validated
        let layer1 = consignment.genesis().chain_net.layer1();
        let mut headers = HashMap::new();
        let mut statuses: BTreeMap<Txid, WitnessStatus> = bmap![];
        // proofs that could not be verified, with whether they were refuted;
        // unvetted status is decided inside the transaction below
        let mut unverified_proofs: BTreeMap<Txid, (SpvProof, bool)> = bmap![];
        let mut consignment_bundles: Vec<(Txid, BundleId, BTreeSet<OpId>)> =
            Vec::with_capacity(consignment.bundles.len());
        for witness_bundle in consignment.bundled_witnesses() {
            let witness_id = witness_bundle.witness_id();
            let bundle = witness_bundle.bundle();
            consignment_bundles.push((
                witness_id,
                bundle.bundle_id(),
                bundle.known_transitions_opids(),
            ));
            if statuses.contains_key(&witness_id) {
                continue;
            }
            let check = Self::resolve_witness_spv(
                &resolver,
                &witness_bundle.tx,
                witness_bundle.spv_proof.as_ref(),
                layer1,
                &mut headers,
            )
            .map_err(|e| StockError::WitnessUnresolved(witness_id, e))?;
            if matches!(check, SpvCheck::Refuted | SpvCheck::Uncheckable) {
                if let Some(proof) = &witness_bundle.spv_proof {
                    unverified_proofs
                        .insert(witness_id, (proof.clone(), matches!(check, SpvCheck::Refuted)));
                }
            }
            let status = match check {
                SpvCheck::Confirmed(status) => status,
                SpvCheck::Absent | SpvCheck::Uncheckable | SpvCheck::Refuted => resolver
                    .resolve_witness(witness_id)
                    .map_err(|e| StockError::WitnessUnresolved(witness_id, e))?,
            };
            statuses.insert(witness_id, status);
        }

        // re-resolve known alternatives when the consignment witness is not
        // valid, so a stale ord does not drop the bundle. This only chooses
        // what to resolve; whether the bundle still has a valid witness is
        // decided inside the transaction. Stored ords are unused: `statuses`
        // already holds a fresher resolution
        for (witness_id, bundle_id, _) in &consignment_bundles {
            if statuses
                .get(witness_id)
                .is_some_and(|status| status.witness_ord().is_valid())
            {
                continue;
            }
            let alt_witness_ids: BTreeSet<Txid> = match self.bundle_info(*bundle_id) {
                Ok((witness_ids, _)) => witness_ids,
                // the bundle is not known yet, so it has no other witnesses
                Err(StockError::Inconsistency(Inconsistency::BundleWitnessUnknown(_))) => {
                    bset![]
                }
                Err(e) => return Err(e),
            };
            for alt_witness_id in alt_witness_ids {
                if let btree_map::Entry::Vacant(e) = statuses.entry(alt_witness_id) {
                    let status = resolver
                        .resolve_witness(alt_witness_id)
                        .map_err(|e| StockError::WitnessUnresolved(alt_witness_id, e))?;
                    e.insert(status);
                }
                if statuses
                    .get(&alt_witness_id)
                    .is_some_and(|status| status.witness_ord().is_valid())
                {
                    break;
                }
            }
        }

        // everything the chain had to say has been said; from here on the
        // unit of work runs inside one transaction
        let stale = self.store_transaction(move |s| {
            // reveal the terminal seals this stock knows the secret of
            let consignment = consignment.reveal_terminal_seals(
                consignment_bundles
                    .iter()
                    .map(|(_, bundle_id, _)| *bundle_id),
                |secret| s.store.seal_of_secret(secret).map_err(StockError::Store),
            )?;

            // witness ords as they will be once the consignment is consumed:
            // every consignment witness, and every alternative the pre-pass
            // re-resolved, carries its fresh resolution
            let mut witnesses: BTreeMap<Txid, WitnessOrd> = statuses
                .iter()
                .map(|(id, status)| (*id, status.witness_ord()))
                .collect();

            // collect the bundles left without any valid witness
            let mut bundles_without_witness: Vec<BundleId> = vec![];
            for (witness_id, bundle_id, _) in &consignment_bundles {
                if witnesses.get(witness_id).is_some_and(|ord| ord.is_valid()) {
                    continue;
                }
                let alts: BTreeSet<Txid> = match s.bundle_info(*bundle_id) {
                    Ok((witness_ids, _)) => witness_ids,
                    // the bundle is not known yet, so it has no other witnesses
                    Err(StockError::Inconsistency(Inconsistency::BundleWitnessUnknown(_))) => {
                        bset![]
                    }
                    Err(e) => return Err(e),
                };
                let unresolved: BTreeSet<Txid> = alts
                    .iter()
                    .filter(|id| !witnesses.contains_key(*id))
                    .copied()
                    .collect();
                witnesses.extend(
                    s.store
                        .witness_ords(&unresolved)
                        .map_err(StockError::Store)?,
                );
                if !alts
                    .iter()
                    .any(|id| witnesses.get(id).is_some_and(|ord| ord.is_valid()))
                {
                    bundles_without_witness.push(*bundle_id);
                }
            }

            // stale consignment: persist the fresh chain knowledge, then
            // refuse. The error is returned after this transaction commits, so
            // that knowledge is not rolled back with it
            if !bundles_without_witness.is_empty() {
                // persist fresh ords of witnesses already in the store
                let resolved_ids: BTreeSet<Txid> = statuses.keys().copied().collect();
                let known_witness_ids = s
                    .store
                    .witness_ords(&resolved_ids)
                    .map_err(StockError::Store)?;
                for (witness_id, status) in &statuses {
                    if known_witness_ids.contains_key(witness_id) {
                        s.set_witness_ord(*witness_id, status.witness_ord())?;
                    }
                }
                // set the known operations of the bundles left without a valid
                // witness as invalid, together with all their descendants
                let mut visited = bset!();
                for bundle_id in &bundles_without_witness {
                    for opid in s.ops_in_bundle(*bundle_id)? {
                        s.set_ops_as_invalid(opid, &mut visited)?;
                    }
                }
                return Ok(true);
            }

            // the consignment carries only its schema id: the schema itself
            // must already be in the store, imported out-of-band via a schema
            // definition
            s.load_imported_schema(consignment.schema_id())?;

            // do not store a proof that failed to verify, or that nothing here
            // could. Keep an already-stored one on `Uncheckable` (headers
            // unavailable, not a bad proof); drop a refuted one even if stored.
            // The store is read here, before consume overwrites it: unverified
            // proofs are split into those stripped from the consignment below
            // and those dropped here.
            let mut unstorable: BTreeSet<Txid> = bset![];
            for (witness_id, (proof, refuted)) in unverified_proofs {
                let stored = s
                    .store
                    .witness_spv_proof(witness_id)
                    .is_ok_and(|stored| stored.as_ref() == Some(&proof));
                if refuted || !stored {
                    unstorable.insert(witness_id);
                }
                // the store holds this very proof, from a consignment it
                // verified in or a retrieval of its own, and the chain has now
                // refuted it. A proof it holds which is not this one is left
                // alone: nothing here checked it
                if refuted && stored {
                    s.set_spv_proof(witness_id, None)?;
                }
            }

            // consume the consignment
            let contract_id = consignment.genesis.contract_id();
            s.consume_genesis(contract_id, consignment.genesis)?;
            for (mut witness_bundle, (witness_id, bundle_id, _)) in
                consignment.bundles.into_iter().zip(&consignment_bundles)
            {
                let witness_ord = statuses
                    .get(witness_id)
                    .expect("every consignment witness is resolved above")
                    .witness_ord();
                // `consume_witness` adopts an incoming proof whenever the store
                // has none, and has no way of telling a checked proof from an
                // unchecked one: the unvetted ones are kept from reaching it
                if unstorable.contains(witness_id) {
                    witness_bundle.spv_proof = None;
                }
                s.consume_witness_bundle(
                    contract_id,
                    witness_bundle,
                    *witness_id,
                    *bundle_id,
                    witness_ord,
                )?;
            }

            // the consignment was validated and all its bundles have a valid
            // witness: revalidate any of its operations that a reorg had
            // previously set as invalid, together with their descendants
            let touched: BTreeSet<OpId> = consignment_bundles
                .iter()
                .flat_map(|(_, _, opids)| opids.iter().copied())
                .collect();
            if s.any_op_invalid(&touched)? {
                let mut invalid_ops = s.all_invalid_op_ids()?;
                let mut maybe_became_valid_opids = touched;
                for (_, bundle_id, opids) in &consignment_bundles {
                    for opid in opids {
                        s.maybe_update_ops_as_valid(
                            *opid,
                            *bundle_id,
                            &mut invalid_ops,
                            &mut maybe_became_valid_opids,
                        )?;
                    }
                }
            }

            Ok(false)
        })?;

        if stale {
            return Err(StockError::AbsentValidWitness);
        }

        Ok(())
    }

    /// Imports fascia into the store.
    ///
    /// Part of the transfer workflow. Called once PSBT is completed and an RGB
    /// fascia containing anchor and all state transitions is exported from
    /// it.
    ///
    /// Must be called before the consignment is created, when witness
    /// transaction is not yet mined.
    pub fn consume_fascia<WP: WitnessOrdProvider>(
        &mut self,
        fascia: Fascia,
        witness_ord_provider: WP,
    ) -> Result<(), StockError<S, FasciaError>> {
        let witness_id = fascia.witness_id();
        let witness_ord = witness_ord_provider
            .witness_ord(witness_id)
            .map_err(|e| StockError::<S, FasciaError>::WitnessUnresolved(witness_id, e))?;
        self.store_transaction(move |s| {
            s.consume_witness(fascia.seal_witness())?;

            for (contract_id, bundle) in fascia.into_bundles() {
                let bundle_id = bundle.bundle_id();
                bundle
                    .check_opid_commitments()
                    .map_err(|_| FasciaError::InvalidBundle(contract_id, bundle_id))?;

                s.index_bundle(contract_id, &bundle, witness_id, bundle_id)?;
                s.update_from_bundle(contract_id, &bundle, witness_id, witness_ord, bundle_id)?;
                s.consume_bundle(bundle, bundle_id)?;
            }
            Ok(())
        })
    }

    fn transition(&self, opid: OpId) -> Result<Transition, StockError<S, ConsignError>> {
        let bundle_id = self.bundle_id_for_op(opid)?;
        let bundle = self.bundle(bundle_id)?;
        bundle
            .get_transition(opid)
            .cloned()
            .ok_or(ConsignError::Concealed(bundle_id, opid).into())
    }

    /// Builds the [`WitnessBundle`] for `bundle_id`, revealing only `opid`.
    ///
    /// The bundle contract and its valid witness are provided by the caller,
    /// which has already resolved them.
    ///
    /// The SPV proof attached is the one from the store. A mined witness the store
    /// has no proof for is recorded in `pending_spv` instead of being resolved here:
    /// fetching it would talk to the resolver while composition still holds a
    /// read transaction. [`Stock::attach_spv_proofs`] fetches those once the
    /// transaction is released.
    ///
    /// A proof coming from the store wins over the resolver and is shipped as is, without
    /// being checked against the chain. Reconciling the store with a reorg is the job of
    /// [`Stock::update_witnesses`], which drops the proofs a reorg invalidated; even in
    /// the window before it notices one, the worst a stale proof costs the receiver is
    /// resolving the witness TX, which is what it would do anyway had no proof been
    /// attached.
    fn witness_bundle(
        &self,
        bundle_id: BundleId,
        opid: OpId,
        contract_id: ContractId,
        (witness_id, witness_ord): (Txid, WitnessOrd),
        pending_spv: &mut BTreeSet<Txid>,
    ) -> Result<(WitnessBundle, u32), StockError<S, ConsignError>> {
        let bundle = self
            .bundle(bundle_id)?
            .to_concealed_except(opid)
            .map_err(|e| StockError::from(ConsignError::Transition(e)))?;
        let witness = self.witness(witness_id)?;
        let tx = witness.tx.clone();
        let Ok(mpc_proof) = witness.mpc_merkle_block.to_merkle_proof(contract_id.into()) else {
            return Err(Inconsistency::WitnessMissesContract(
                witness_id,
                bundle_id,
                contract_id,
                witness.dbc_proof.method(),
            )
            .into());
        };
        let anchor = Anchor::new(mpc_proof, witness.dbc_proof.clone());

        let spv_proof = witness.spv_proof.clone();
        // a non-mined witness has no proof to retrieve. This is what leaves the
        // witness of the transfer being composed without one, as it is not
        // broadcast yet.
        if spv_proof.is_none() && matches!(witness_ord, WitnessOrd::Mined(_)) {
            pending_spv.insert(witness_id);
        }

        let height = match witness_ord {
            WitnessOrd::Mined(pos) => pos.height().into(),
            WitnessOrd::Tentative => u32::MAX - 1,
            WitnessOrd::Ignored => u32::MAX,
            WitnessOrd::Archived => unreachable!("select_valid_witness prevents this"),
        };

        Ok((
            WitnessBundle {
                tx,
                anchor,
                bundle,
                spv_proof,
            },
            height,
        ))
    }

    /// Remembers a secret seal so later consignments can reveal it.
    pub fn store_secret_seal(&mut self, seal: GraphSeal) -> Result<(), StockError<S>> {
        self.store_transaction(|s| {
            s.store
                .put_secret_seal(&seal, seal.conceal())
                .map_err(StockError::Store)
        })
    }

    /// The transitions spending `opid`'s outputs, straight from the spend-edge
    /// index: the edges were recorded per known transition when its bundle was
    /// indexed, so reading them back needs no bundle decoded. An operation with
    /// no spenders yet is an empty set, not an error.
    fn op_children(&self, opid: OpId) -> Result<BTreeSet<(OpId, BundleId)>, StockError<S>> {
        self.store.child_ops_of_op(opid).map_err(StockError::Store)
    }

    fn set_ops_as_invalid(
        &mut self,
        opid: OpId,
        visited: &mut BTreeSet<OpId>,
    ) -> Result<(), StockError<S>> {
        // descendant trees of different operations can overlap and converge;
        // visit each operation only once per update
        // the visited set is local to the update on purpose: operations
        // already invalid from previous updates must still be re-visited,
        // since new descendants may have been added in the meantime
        if !visited.insert(opid) {
            return Ok(());
        }
        // add operation to set of invalid operations
        self.update_op(opid, false)?;
        // recursively set all descendant operations as invalid
        for (child_opid, _) in self.op_children(opid)? {
            self.set_ops_as_invalid(child_opid, visited)?;
        }
        Ok(())
    }

    fn maybe_update_ops_as_valid(
        &mut self,
        opid: OpId,
        bundle_id: BundleId,
        invalid_ops: &mut BTreeSet<OpId>,
        maybe_became_valid_opids: &mut BTreeSet<OpId>,
    ) -> Result<bool, StockError<S>> {
        // the operation has to belong to the bundle it is being weighed under.
        // Asked of the op->bundle index, as are the inputs below: this walk
        // needs a transition's parents and nothing else of it, and the index
        // holds exactly that - where loading the bundle would decode every
        // transition in it, once per operation visited
        if self.bundle_id_for_op(opid)? != bundle_id {
            return Err(Inconsistency::OperationAbsent(opid).into());
        }

        // a valid operation needs a valid witness for its bundle
        let mut valid = self.bundle_has_valid_witness(bundle_id)?;

        // recursively visit operation ancestors
        if valid {
            let inputs = self
                .store
                .input_opouts_for_op(opid)
                .map_err(StockError::Store)?;
            for input in &inputs {
                let input_opid = input.op;
                // process parent first if its status is also uncertain
                if maybe_became_valid_opids.contains(&input_opid) {
                    let input_bundle_id = self.bundle_id_for_op(input_opid)?;
                    if !self.maybe_update_ops_as_valid(
                        input_opid,
                        input_bundle_id,
                        invalid_ops,
                        maybe_became_valid_opids,
                    )? {
                        valid = false;
                        break;
                    }
                // a single invalid parent is enough to consider the operation as invalid
                } else if invalid_ops.contains(&input_opid) {
                    valid = false;
                    break;
                }
            }
        }

        // remove operation since at this point we are sure about its status
        maybe_became_valid_opids.remove(&opid);

        if valid {
            // remove operation from set of invalid operations
            self.update_op(opid, true)?;
            invalid_ops.remove(&opid);
            // recursively visit operation descendants to check if they became valid as well
            for (child_opid, child_bundle_id) in self.op_children(opid)? {
                // a child may have already been settled as valid earlier in
                // this update, when reached through another revalidated
                // parent; don't re-walk its subtree
                if !invalid_ops.contains(&child_opid)
                    && !maybe_became_valid_opids.contains(&child_opid)
                {
                    continue;
                }
                self.maybe_update_ops_as_valid(
                    child_opid,
                    child_bundle_id,
                    invalid_ops,
                    maybe_became_valid_opids,
                )?;
            }
        }

        Ok(valid)
    }

    /// Re-resolves a witness against the chain.
    ///
    /// Read-only, and called with no store transaction open: this is the only
    /// step of [`Stock::update_witnesses`] which talks to the network, and
    /// running it inside the transaction would hold the store's write lock for
    /// as long as the resolver takes to answer for every witness of the stock.
    /// The writes it implies are applied afterwards by
    /// [`Stock::apply_witness_ord`].
    fn resolve_witness_ord(
        &self,
        resolver: &impl ResolveWitness,
        id: Txid,
        layer1: Layer1,
        headers: &mut HashMap<NonZeroU32, Header>,
    ) -> Result<WitnessOrdUpdate, StockError<S>> {
        // when the witness has a stored SPV proof, its status is checked against
        // that proof, so that a client with no access to a TX indexer can still
        // detect a reorg affecting it
        let spv_check = match self.store.witness_tx(id).map_err(StockError::Store)? {
            Some(tx) => {
                let proof = self
                    .store
                    .witness_spv_proof(id)
                    .map_err(StockError::Store)?;
                Self::resolve_witness_spv(resolver, &tx, proof.as_ref(), layer1, headers)
                    .map_err(|e| StockError::WitnessUnresolved(id, e))?
            }
            None => SpvCheck::Absent,
        };
        let proof_refuted = matches!(spv_check, SpvCheck::Refuted);
        let ord = match spv_check {
            SpvCheck::Confirmed(status) => status,
            SpvCheck::Absent | SpvCheck::Uncheckable | SpvCheck::Refuted => resolver
                .resolve_witness(id)
                .map_err(|e| StockError::WitnessUnresolved(id, e))?,
        }
        .witness_ord();
        Ok(WitnessOrdUpdate { ord, proof_refuted })
    }

    /// Stores what [`Stock::resolve_witness_ord`] resolved for a witness,
    /// updating `ord` in place and reporting whether the witness crossed
    /// validity.
    ///
    /// Must run inside a store transaction already opened by the caller. It
    /// writes the witness ord and drops a refuted proof together, and a
    /// failure halfway through is only safe if those writes roll back as one.
    /// It does not open that transaction itself.
    fn apply_witness_ord(
        &mut self,
        id: Txid,
        ord: &mut WitnessOrd,
        update: WitnessOrdUpdate,
    ) -> Result<WitnessOrdChange, StockError<S>> {
        let WitnessOrdUpdate {
            ord: new,
            proof_refuted,
        } = update;
        // a proof a reorg has refuted is dropped whichever ord the witness ends
        // up with, so the store keeps only proofs which verified
        if proof_refuted {
            self.set_spv_proof(id, None)?;
        }
        if *ord == new {
            return Ok(WitnessOrdChange::Kept);
        }
        let bundle_valid = match (*ord, new) {
            (WitnessOrd::Archived, _) => Some(true),
            (_, WitnessOrd::Archived) => Some(false),
            _ => None,
        };
        // report witnesses that became valid or invalid. The bundles come from
        // the index, not from decoding the witness record's merkle block: the
        // index lists the bundles this stock tracks, which are the only ones
        // whose operations there are to re-weigh
        let mut change = WitnessOrdChange::Kept;
        if let Some(valid) = bundle_valid {
            let bundle_ids = self
                .store
                .bundles_of_witness(id)
                .map_err(StockError::Store)?;
            change = if valid {
                WitnessOrdChange::BecameValid(bundle_ids)
            } else {
                WitnessOrdChange::BecameInvalid(bundle_ids)
            };
        }
        // save the changed witness ord
        self.set_witness_ord(id, new)?;
        *ord = new;
        Ok(change)
    }

    /// Re-resolves known witnesses and updates operation validity accordingly.
    ///
    /// Witnesses mined below `after_height` are skipped unless listed in
    /// `force_witnesses`. Ignored witnesses are skipped unless forced.
    pub fn update_witnesses(
        &mut self,
        resolver: impl ResolveWitness,
        after_height: u32,
        force_witnesses: Vec<Txid>,
    ) -> Result<UpdateRes, StockError<S>> {
        let after_height = NonZeroU32::new(after_height).unwrap_or(NonZeroU32::MIN);
        // needed to turn an SPV proof's height into a `WitnessPos`; all the contracts of a
        // stock live on the same chain, so any genesis answers for all of them
        let layer1 = self
            .geneses()
            .next()
            .transpose()?
            .map(|genesis| genesis.chain_net.layer1())
            .unwrap_or(Layer1::Bitcoin);
        // pick what to ask the chain about
        let mut candidates = self
            .store
            .witness_ords_to_refresh(after_height)
            .map_err(StockError::Store)?;
        let forced: BTreeSet<Txid> = force_witnesses.into_iter().collect();
        // of the forced ones, only those the store knows: an unknown witness
        // has nothing stored for a resolution to update
        candidates.extend(
            self.store
                .witness_ords(&forced)
                .map_err(StockError::Store)?
                .into_keys(),
        );

        // 1. re-resolve the witnesses against the chain, outside any transaction
        let mut failed = map![];
        let mut updates = BTreeMap::new();
        let mut headers = HashMap::new();
        for id in &candidates {
            match self.resolve_witness_ord(&resolver, *id, layer1, &mut headers) {
                Ok(update) => {
                    updates.insert(*id, update);
                }
                // a witness the resolver cannot answer for is reported back and
                // left with the ord it already had
                Err(err) => {
                    failed.insert(*id, err.to_string());
                }
            }
        }
        let succeeded = updates.len();

        // Wrap the whole update in one transaction so a mid-way error rolls the
        // partial witness/bundle changes back instead of leaving them committed.
        self.store_transaction(move |s| {
            let mut became_invalid_witnesses = bmap!();
            let mut became_valid_witnesses = bmap!();
            // the ords as they stand now that this unit of work holds the write
            // lock, not as they stood before the resolver was waited on: a
            // resolution for a witness which has since been removed is dropped
            // on the floor, and one which has since changed is applied to what
            // is actually stored. Only the witnesses actually resolved are read
            // - the rest of the table is nothing this call decides about
            let resolved: BTreeSet<Txid> = updates.keys().copied().collect();
            let mut witnesses = s.store.witness_ords(&resolved).map_err(StockError::Store)?;
            // 2. store the resolved witness ords
            for (id, update) in updates {
                // absent: the witness was removed while the resolver was being
                // waited on, so there is nothing to update
                let Some(ord) = witnesses.get_mut(&id) else {
                    continue;
                };
                match s.apply_witness_ord(id, ord, update)? {
                    WitnessOrdChange::BecameValid(bundle_ids) => {
                        became_valid_witnesses.insert(id, bundle_ids);
                    }
                    WitnessOrdChange::BecameInvalid(bundle_ids) => {
                        became_invalid_witnesses.insert(id, bundle_ids);
                    }
                    WitnessOrdChange::Kept => {}
                }
            }

            // 3. set invalidity of operations
            let mut visited = bset!();
            for bundle_ids in became_invalid_witnesses.values() {
                for bundle_id in bundle_ids {
                    // set the bundle operations as invalid only if there are no valid witnesses
                    // associated to the bundle
                    if !s.bundle_has_valid_witness(*bundle_id)? {
                        // set all the bundle operations and their descendants as invalid
                        for opid in s.ops_in_bundle(*bundle_id)? {
                            s.set_ops_as_invalid(opid, &mut visited)?;
                        }
                    }
                }
            }

            // 4. set validity of operations
            let mut maybe_became_valid_opids = bset!();
            // get all operations that became invalid and ones that were already invalid
            let mut invalid_ops_pre = s.all_invalid_op_ids()?;
            for bundle_ids in became_valid_witnesses.values() {
                for bundle_id in bundle_ids {
                    // store operations that may become valid (to be sure their ancestors are
                    // checked)
                    maybe_became_valid_opids.extend(s.ops_in_bundle(*bundle_id)?);
                }
            }
            for bundle_ids in became_valid_witnesses.values() {
                for bundle_id in bundle_ids {
                    // check if the bundle operations and their descendants are now valid
                    for opid in s.ops_in_bundle(*bundle_id)? {
                        s.maybe_update_ops_as_valid(
                            opid,
                            *bundle_id,
                            &mut invalid_ops_pre,
                            &mut maybe_became_valid_opids,
                        )?;
                    }
                }
            }
            Ok(())
        })?;
        Ok(UpdateRes { succeeded, failed })
    }

    /// Attach an SPV proof to an already-known witness TX.
    ///
    /// Consignments produced afterwards carry the proof, letting the receiver verify that
    /// the witness is mined from a block header alone, without asking an indexer for the
    /// TX. Returns whether anything changed.
    pub fn store_spv_proof(
        &mut self,
        witness_id: Txid,
        proof: SpvProof,
    ) -> Result<bool, StockError<S>> {
        self.store_transaction(|s| s.set_spv_proof(witness_id, Some(&proof)))
    }

    /// Keeps the SPV proofs a composition retrieved, returning how many
    /// witnesses gained or changed one.
    ///
    /// Composing a transfer retrieves the proofs the store was missing and
    /// attaches them to the consignment without storing them - see
    /// [`Stock::transfer`] - so a wallet is not made to keep a proof for every
    /// witness it knows. One that does want them kept passes the
    /// [`RetrievedSpvProofs`] the composition returned: they are stored without
    /// the resolver being asked a second time, and without touching the proofs
    /// which came out of the store to begin with.
    ///
    /// All of them in one transaction. A witness this stock does not know is
    /// skipped, and a proof it already holds is left alone rather than
    /// rewritten. Nothing is verified here: a proof which does not hold up is
    /// dropped by [`Stock::update_witnesses`](Self::update_witnesses) when it
    /// next checks the witness against the chain, as for any stored proof.
    pub fn store_spv_proofs(
        &mut self,
        proofs: impl IntoIterator<Item = (Txid, SpvProof)>,
    ) -> Result<usize, StockError<S>> {
        let proofs: Vec<(Txid, SpvProof)> = proofs.into_iter().collect();
        self.store_transaction(move |s| {
            let mut stored = 0;
            for (witness_id, proof) in &proofs {
                stored += usize::from(s.set_spv_proof(*witness_id, Some(proof))?);
            }
            Ok(stored)
        })
    }

    /// Replaces the SPV proof stored for a witness, reporting whether anything
    /// changed. A witness the store does not know is left alone.
    ///
    /// Not a unit of work of its own: it is called both from the public
    /// [`Stock::store_spv_proof`], which wraps it in a transaction, and from
    /// within larger ones. The proof is written on its own, without the witness
    /// it belongs to being read or rewritten around it.
    fn set_spv_proof(
        &mut self,
        witness_id: Txid,
        proof: Option<&SpvProof>,
    ) -> Result<bool, StockError<S>> {
        self.store
            .set_witness_spv_proof(witness_id, proof)
            .map_err(StockError::Store)
    }

    /// Sets the ord of a known witness.
    pub fn upsert_witness(
        &mut self,
        witness_id: Txid,
        witness_ord: WitnessOrd,
    ) -> Result<(), StockError<S>> {
        self.store_transaction(move |s| s.set_witness_ord(witness_id, witness_ord))
    }

    fn _check_bundle_history(
        &self,
        bundle_id: &BundleId,
        safe_height: NonZeroU32,
        contract_history: &mut HashMap<ContractId, HashMap<u32, HashSet<Txid>>>,
        visited: &mut BTreeSet<BundleId>,
    ) -> Result<(), StockError<S>> {
        // ancestries of sibling assignments converge on shared history; each
        // bundle is weighed once per call, not once per path reaching it
        if !visited.insert(*bundle_id) {
            return Ok(());
        }
        let (bundle_witness_ids, contract_id) = self.bundle_info(*bundle_id)?;
        let (witness_id, ord) = self.select_valid_witness(bundle_witness_ids)?;
        match ord {
            WitnessOrd::Mined(witness_pos) => {
                let witness_height = witness_pos.height();
                if witness_height > safe_height {
                    contract_history
                        .entry(contract_id)
                        .or_default()
                        .entry(witness_height.into())
                        .or_default()
                        .insert(witness_id);
                }
            }
            WitnessOrd::Tentative | WitnessOrd::Ignored | WitnessOrd::Archived => {
                contract_history
                    .entry(contract_id)
                    .or_default()
                    .entry(0)
                    .or_default()
                    .insert(witness_id);
            }
        }

        // recursively check bundle ancestors, walked over the index alone:
        // the walk needs each known transition's inputs and nothing else of
        // the bundle, and the spend-edge rows hold exactly that
        for opid in self.ops_in_bundle(*bundle_id)? {
            let inputs = self
                .store
                .input_opouts_for_op(opid)
                .map_err(StockError::Store)?;
            for input in inputs {
                let input_bundle_id = match self.bundle_id_for_op(input.op) {
                    Ok(id) => Some(id),
                    Err(StockError::Inconsistency(Inconsistency::OpBundleAbsent(_))) => {
                        // reached genesis
                        None
                    }
                    Err(e) => return Err(e),
                };

                if let Some(input_bundle_id) = input_bundle_id {
                    self._check_bundle_history(
                        &input_bundle_id,
                        safe_height,
                        contract_history,
                        visited,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Returns, per contract, the witnesses above `safe_height` that affect an outpoint.
    pub fn get_outpoint_unsafe_history(
        &self,
        outpoint: Outpoint,
        safe_height: NonZeroU32,
    ) -> Result<HashMap<ContractId, UnsafeHistoryMap>, StockError<S>> {
        let _read_tx = ReadTransaction::open(&self.store).map_err(StockError::Store)?;
        let mut contract_history: HashMap<ContractId, HashMap<u32, HashSet<Txid>>> = HashMap::new();
        let mut visited = bset![];

        for state in self.assignments_by_contract([outpoint])?.into_values() {
            for opid in state
                .values()
                .flat_map(|assigns| assigns.keys().map(|opout| opout.op))
            {
                let bundle_id = self.bundle_id_for_op(opid)?;
                self._check_bundle_history(
                    &bundle_id,
                    safe_height,
                    &mut contract_history,
                    &mut visited,
                )?;
            }
        }

        Ok(contract_history)
    }

    /// Checks that two contracts link to each other as parent and child.
    pub fn validate_contracts_link<Parent: LinkableIssuerWrapper, Child: LinkableIssuerWrapper>(
        &self,
        parent_contract_id: ContractId,
        child_contract_id: ContractId,
    ) -> Result<(), StockError<S>> {
        let _read_tx = ReadTransaction::open(&self.store).map_err(StockError::Store)?;
        let parent_links_to_child = self
            .schema_wrapper::<<Parent as LinkableIssuerWrapper>::Wrapper<_>>(parent_contract_id)?
            .link_to()?
            .ok_or(LinkError::NoValue)?
            == child_contract_id;
        let child_links_to_parent = self
            .schema_wrapper::<<Child as LinkableIssuerWrapper>::Wrapper<_>>(child_contract_id)?
            .link_from()?
            .ok_or(LinkError::NoValue)?
            == parent_contract_id;
        if parent_links_to_child && child_links_to_parent {
            Ok(())
        } else {
            Err(LinkError::ValueMismatch.into())
        }
    }

    /// The definition a stored schema was imported from, out of the libraries
    /// the store keeps for all of its schemata.
    ///
    /// The AluVM libraries are collected over the closure of the calls the
    /// schema's entry points make, not just the entry points themselves: a
    /// library may call into another, and [`SchemaRules::with`] requires
    /// everything the schema can reach. The type libraries are not reachable
    /// from the schema at all - it commits to semantic ids, not to the libraries
    /// defining them - so they are read back by the link the import recorded.
    fn assemble_schema_definition(
        &self,
        schema: Schema,
    ) -> Result<SchemaDefinition, StockError<S>> {
        let schema_id = schema.schema_id();
        let libs = self.store.type_libs(schema_id).map_err(StockError::Store)?;
        let libs = TypeLibs::try_from(libs).map_err(|_| DataError::TooManyTypeLibs(schema_id))?;

        let mut scripts = BTreeMap::<LibId, Lib>::new();
        let mut queue = schema.libs().collect::<Vec<_>>();
        while let Some(id) = queue.pop() {
            if scripts.contains_key(&id) {
                continue;
            }
            let lib = self
                .store
                .aluvm_lib(id)
                .map_err(StockError::Store)?
                .ok_or(Inconsistency::LibAbsent(id))?;
            queue.extend(lib.libs.iter().copied());
            scripts.insert(id, lib);
        }
        let scripts = Scripts::try_from(scripts).map_err(|_| DataError::TooManyLibs(schema_id))?;

        Ok(SchemaDefinition::new(schema, libs, scripts))
    }

    /// The verified rules of an already-loaded schema: the cached ones, or the
    /// ones reassembling and verifying its definition yields.
    fn rules_of(&self, schema: Schema) -> Result<SchemaRules, StockError<S>> {
        let schema_id = schema.schema_id();
        if let Some(rules) = self.cached_rules(schema_id) {
            return Ok(rules);
        }
        let rules = self
            .assemble_schema_definition(schema)?
            .verify()
            .map_err(|e| DataError::SchemaDef(schema_id, Box::new(e)))?;
        self.cache_rules(schema_id, &rules);
        Ok(rules)
    }

    /// The rules cached for `schema_id`, if they have been derived already.
    ///
    /// A poisoned cache reads as an empty one, and writes to it are dropped:
    /// it holds nothing which cannot be derived again from the store, so a
    /// panic in another thread costs the derivation and not the stock.
    fn cached_rules(&self, schema_id: SchemaId) -> Option<SchemaRules> {
        self.rules.lock().ok()?.get(&schema_id).cloned()
    }

    /// Caches the rules of `schema_id`. See [`Self::cached_rules`].
    fn cache_rules(&self, schema_id: SchemaId, rules: &SchemaRules) {
        if let Ok(mut cache) = self.rules.lock() {
            cache.insert(schema_id, rules.clone());
        }
    }

    /// The verified rules a contract was issued under.
    fn contract_schema_rules(&self, contract_id: ContractId) -> Result<SchemaRules, StockError<S>> {
        let _read_tx = ReadTransaction::open(&self.store).map_err(StockError::Store)?;
        let schema = self
            .store
            .contract_schema(contract_id)
            .map_err(StockError::Store)?
            .ok_or(Inconsistency::ContractAbsent(contract_id))?;
        self.rules_of(schema)
    }

    fn load_schema(&self, schema_id: SchemaId) -> Result<Schema, StockError<S>> {
        self.store
            .schema(schema_id)
            .map_err(StockError::Store)?
            .ok_or_else(|| Inconsistency::SchemaAbsent(schema_id).into())
    }

    fn geneses(&self) -> impl Iterator<Item = Result<Genesis, StockError<S>>> + '_ {
        self.store.geneses().map(|r| r.map_err(StockError::Store))
    }

    fn genesis(&self, contract_id: ContractId) -> Result<Genesis, StockError<S>> {
        self.store
            .genesis(contract_id)
            .map_err(StockError::Store)?
            .ok_or_else(|| Inconsistency::ContractAbsent(contract_id).into())
    }

    fn bundle(&self, bundle_id: BundleId) -> Result<TransitionBundle, StockError<S>> {
        self.store
            .bundle(bundle_id)
            .map_err(StockError::Store)?
            .ok_or_else(|| Inconsistency::BundleAbsent(bundle_id).into())
    }

    fn witness(&self, witness_id: Txid) -> Result<SealWitness, StockError<S>> {
        self.store
            .witness(witness_id)
            .map_err(StockError::Store)?
            .ok_or_else(|| Inconsistency::WitnessAbsent(witness_id).into())
    }

    /// Consumes a consignment's genesis in one pass: contract state, indexes
    /// and the store, where it is merged into the genesis already known, if
    /// any.
    ///
    /// Must run inside a store transaction already opened by the caller. It
    /// writes the contract state, the indexes and the store record together,
    /// and a failure halfway through is only safe if those writes roll back as
    /// one. It does not open that transaction itself.
    fn consume_genesis(
        &mut self,
        contract_id: ContractId,
        genesis: Genesis,
    ) -> Result<(), StockError<S>> {
        // store, first: the genesis row is what registers the contract, and the
        // index writes below refuse to run for one the store does not hold
        let merged = match self.store.genesis(contract_id).map_err(StockError::Store)? {
            Some(mut g) => {
                g.merge_reveal(&genesis)
                    .map_err(|e| StockError::Data(e.into()))?;
                Some(g)
            }
            None => None,
        };
        self.store
            .put_genesis(merged.as_ref().unwrap_or(&genesis))
            .map_err(StockError::Store)?;
        // contract state
        self.add_genesis(contract_id, &genesis)?;
        // indexes
        let opid = genesis.id();
        self.index_assignments(contract_id, opid, None, &genesis.assignments)
    }

    /// Consumes one witness bundle of a consignment in a single pass over its
    /// data.
    ///
    /// Must run inside a store transaction already opened by the caller. It
    /// writes the witness ord, the contract state, the indexes and the store
    /// record together, and a failure halfway through is only safe if those
    /// writes roll back as one. It does not open that transaction itself.
    ///
    /// The ids are the caller's to provide, computed once per bundle rather
    /// than re-hashed by each subsystem.
    fn consume_witness_bundle(
        &mut self,
        contract_id: ContractId,
        witness_bundle: WitnessBundle,
        witness_id: Txid,
        bundle_id: BundleId,
        witness_ord: WitnessOrd,
    ) -> Result<(), StockError<S>> {
        let WitnessBundle {
            tx,
            spv_proof,
            anchor,
            bundle,
        } = witness_bundle;
        self.set_witness_ord(witness_id, witness_ord)?;
        for KnownTransition { transition, .. } in &bundle.known_transitions {
            self.add_transition(contract_id, transition, witness_id, bundle_id)?;
        }
        self.index_bundle(contract_id, &bundle, witness_id, bundle_id)?;
        let proto = mpc::ProtocolId::from_byte_array(contract_id.to_byte_array());
        let msg = mpc::Message::from_byte_array(bundle_id.to_byte_array());
        let mpc_merkle_block = MerkleBlock::with(&anchor.mpc_proof, proto, msg)?;
        self.consume_witness(&SealWitness {
            tx,
            mpc_merkle_block,
            dbc_proof: anchor.dbc_proof,
            spv_proof,
        })?;
        self.consume_bundle(bundle, bundle_id)
    }

    /// Store `witness`, merging it into the one already known for the same TX, if any.
    ///
    /// An incoming SPV proof is adopted only when the store has none: two proofs for the
    /// same TX disagree exactly when a reorg moved it, and the one the store holds is the
    /// one that verified when the witnesses were last updated, whereas the incoming one
    /// comes from a counterparty and has not been checked against the chain here. Dropping
    /// it costs nothing: [`Stock::update_witnesses`] discards the stored proof as soon as
    /// it sees the reorg, and the next retrieval replaces it.
    fn consume_witness(&mut self, witness: &SealWitness) -> Result<(), StockError<S>> {
        let merged = match self
            .store
            .witness(witness.witness_id())
            .map_err(StockError::Store)?
        {
            Some(mut w) => {
                let mut incoming = witness.clone();
                if w.spv_proof.is_some() {
                    incoming.spv_proof = None;
                }
                w.merge_reveal(&incoming)?;
                w
            }
            None => witness.clone(),
        };

        self.store.put_witness(&merged).map_err(StockError::Store)
    }

    fn consume_bundle(
        &mut self,
        bundle: TransitionBundle,
        bundle_id: BundleId,
    ) -> Result<(), StockError<S>> {
        let merged = match self.store.bundle(bundle_id).map_err(StockError::Store)? {
            Some(mut b) => {
                b.merge_reveal(&bundle)
                    .map_err(|e| StockError::Data(e.into()))?;
                b
            }
            None => bundle,
        };
        self.store.put_bundle(&merged).map_err(StockError::Store)
    }

    fn ops_in_bundle(&self, bundle_id: BundleId) -> Result<BTreeSet<OpId>, StockError<S>> {
        self.store
            .ops_in_bundle(bundle_id)
            .map_err(StockError::Store)
    }

    fn all_invalid_op_ids(&self) -> Result<BTreeSet<OpId>, StockError<S>> {
        self.store.all_invalid_ops().map_err(StockError::Store)
    }

    fn any_op_invalid(&self, opids: &BTreeSet<OpId>) -> Result<bool, StockError<S>> {
        self.store.any_op_invalid(opids).map_err(StockError::Store)
    }

    fn read_contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<ContractStateSnapshot, StockError<S>> {
        let schema = self
            .store
            .contract_schema(contract_id)
            .map_err(StockError::Store)?
            .ok_or(Inconsistency::ContractAbsent(contract_id))?;
        // one read transaction over the whole read: the snapshot is assembled
        // from several queries and must be of one DB state, not of each DB state they
        // happened to meet
        let _read_tx = ReadTransaction::open(&self.store).map_err(StockError::Store)?;
        ContractStateSnapshot::load(&self.store, contract_id, &schema).map_err(StockError::State)
    }

    fn select_valid_witness(
        &self,
        witness_ids: impl IntoIterator<Item = impl Borrow<Txid>>,
    ) -> Result<(Txid, WitnessOrd), StockError<S>> {
        let mut best_candidate = None;
        for id in witness_ids {
            let id = *id.borrow();
            let ord = self
                .store
                .witness_ord(id)
                .map_err(StockError::Store)?
                .ok_or(Inconsistency::WitnessAbsent(id))?;
            let candidate = (id, ord);
            best_candidate = match best_candidate {
                Some(prev) => Some(min_by_key(prev, candidate, |&(_, ord)| ord)),
                None => Some(candidate),
            };
        }
        let (best_id, best_ord) = best_candidate.expect("one witness ID should always be there");
        if best_ord == WitnessOrd::Archived {
            Err(StockError::AbsentValidWitness)
        } else {
            Ok((best_id, best_ord))
        }
    }

    /// Derives contract state from a bundle closed by `witness_id`, whose ord
    /// and id the caller has already resolved.
    ///
    /// Must run inside a store transaction already opened by the caller. It
    /// writes the witness ord and the derived state together, and a failure
    /// halfway through is only safe if those writes roll back as one. It does
    /// not open that transaction itself.
    fn update_from_bundle(
        &mut self,
        contract_id: ContractId,
        bundle: &TransitionBundle,
        witness_id: Txid,
        witness_ord: WitnessOrd,
        bundle_id: BundleId,
    ) -> Result<(), StockError<S>> {
        if self
            .store
            .genesis(contract_id)
            .map_err(StockError::Store)?
            .is_none()
        {
            return Err(Inconsistency::ContractAbsent(contract_id).into());
        }
        self.set_witness_ord(witness_id, witness_ord)?;
        for KnownTransition { transition, .. } in &bundle.known_transitions {
            self.add_transition(contract_id, transition, witness_id, bundle_id)?;
        }
        Ok(())
    }

    fn set_witness_ord(
        &mut self,
        witness_id: Txid,
        witness_ord: WitnessOrd,
    ) -> Result<(), StockError<S>> {
        self.store
            .put_witness_ord(witness_id, witness_ord)
            .map_err(StockError::Store)
    }

    fn update_op(&mut self, opid: OpId, valid: bool) -> Result<(), StockError<S>> {
        self.store
            .set_op_validity(opid, valid)
            .map_err(StockError::Store)
    }

    // ----- derivation --------------------------------------------------------

    fn add_genesis(
        &mut self,
        contract_id: ContractId,
        genesis: &Genesis,
    ) -> Result<(), StockError<S>> {
        let opid = genesis.id();
        self.insert_global_state(contract_id, opid, genesis.nonce(), None, genesis.globals())?;
        self.insert_assignments(contract_id, opid, None, &genesis.assignments)
    }

    /// Derives contract state from a single transition. The ord of its
    /// witness is the caller's to store, once per witness rather than once
    /// per transition.
    fn add_transition(
        &mut self,
        contract_id: ContractId,
        transition: &Transition,
        witness_id: Txid,
        bundle_id: BundleId,
    ) -> Result<(), StockError<S>> {
        let opid = transition.id();
        self.insert_global_state(
            contract_id,
            opid,
            transition.nonce(),
            Some((bundle_id, transition.transition_type)),
            transition.globals(),
        )?;
        self.insert_assignments(
            contract_id,
            opid,
            Some((witness_id, bundle_id)),
            &transition.assignments,
        )
    }

    /// Takes the bundle rather than an [`OpWitness`]: an entry outlives
    /// whichever transaction currently anchors its bundle, so the witness in an
    /// `OpWitness` is not what it can be stored under. `None` is genesis.
    fn insert_global_state(
        &mut self,
        contract_id: ContractId,
        opid: OpId,
        nonce: u64,
        bundle: Option<(BundleId, TransitionType)>,
        globals: &GlobalState,
    ) -> Result<(), StockError<S>> {
        let (bundle_id, transition_type) = match bundle {
            None => (None, None),
            Some((id, tt)) => (Some(id), Some(tt)),
        };
        for (ty, values) in globals.iter() {
            for (idx, data) in values.iter().enumerate() {
                self.store
                    .put_global(GlobalStateWrite {
                        contract_id,
                        type_id: *ty,
                        opid,
                        index: idx as u16,
                        nonce,
                        bundle_id,
                        transition_type,
                        value: data,
                    })
                    .map_err(StockError::Store)?;
            }
        }
        Ok(())
    }

    /// Stores the revealed allocations of an operation. `witness` is `None` for
    /// genesis, whose seals always resolve to an outpoint on their own; for a
    /// transition it carries the witness and the bundle the allocations belong
    /// to.
    fn insert_assignments<Seal: ExposedSeal>(
        &mut self,
        contract_id: ContractId,
        opid: OpId,
        witness: Option<(Txid, BundleId)>,
        assignments: &Assignments<Seal>,
    ) -> Result<(), StockError<S>> {
        for (ty, typed) in assignments.iter() {
            match typed {
                // Declarative rights carry no state; store an empty blob
                // (VoidState strict-encodes to zero bytes) instead of encoding
                // it per allocation.
                TypedAssigns::Declarative(assigns) => self.insert_assigns(
                    contract_id,
                    opid,
                    *ty,
                    witness,
                    AllocKind::Declarative,
                    assigns,
                    |_| Vec::new(),
                )?,
                TypedAssigns::Fungible(assigns) => self.insert_assigns(
                    contract_id,
                    opid,
                    *ty,
                    witness,
                    AllocKind::Fungible,
                    assigns,
                    enc_state,
                )?,
                TypedAssigns::Structured(assigns) => self.insert_assigns(
                    contract_id,
                    opid,
                    *ty,
                    witness,
                    AllocKind::Structured,
                    assigns,
                    enc_state,
                )?,
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_assigns<Seal: ExposedSeal, State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        opid: OpId,
        ty: AssignmentType,
        witness: Option<(Txid, BundleId)>,
        kind: AllocKind,
        assignments: &[Assign<State, Seal>],
        enc: impl Fn(&State) -> Vec<u8>,
    ) -> Result<(), StockError<S>> {
        // `no` is the index in this type's assignment vector (`Opout::no`)
        for (no, assignment) in assignments.iter().enumerate() {
            let Some((seal, state)) = assignment.to_revealed() else {
                continue;
            };
            // stored as defined: a seal on the witness transaction resolves
            // against every witness of the bundle, not only this one
            let seal = AllocSeal {
                txid: seal.txid(),
                vout: seal.vout(),
            };
            self.store
                .put_allocation(AllocationWrite {
                    contract_id,
                    kind,
                    opout: Opout::new(opid, ty, no as u16),
                    seal,
                    bundle_id: witness.map(|(_, bundle_id)| bundle_id),
                    value: &enc(&state),
                })
                .map_err(StockError::Store)?;
        }
        Ok(())
    }

    fn index_bundle(
        &mut self,
        contract_id: ContractId,
        bundle: &TransitionBundle,
        witness_id: Txid,
        bundle_id: BundleId,
    ) -> Result<(), StockError<S>> {
        self.register_bundle(bundle_id, witness_id, contract_id)?;
        for KnownTransition { opid, transition } in &bundle.known_transitions {
            self.register_operation(*opid, bundle_id)?;
            for input in &transition.inputs {
                self.store
                    .put_op_input(input, *opid, bundle_id)
                    .map_err(StockError::Store)?;
            }
            self.index_assignments(contract_id, *opid, Some(witness_id), &transition.assignments)?;
        }
        Ok(())
    }

    fn register_bundle(
        &mut self,
        bundle_id: BundleId,
        witness_id: Txid,
        contract_id: ContractId,
    ) -> Result<(), StockError<S>> {
        let existing = self
            .store
            .bundle_contract(bundle_id)
            .map_err(StockError::Store)?;
        if let Some(present) = existing.filter(|alt| *alt != contract_id) {
            return Err(Inconsistency::DistinctBundleContract {
                bundle_id,
                present,
                expected: contract_id,
            }
            .into());
        }
        self.store
            .put_bundle_witness(bundle_id, witness_id)
            .map_err(StockError::Store)?;
        self.store
            .put_bundle_contract(bundle_id, contract_id)
            .map_err(StockError::Store)?;
        Ok(())
    }

    fn register_operation(&mut self, opid: OpId, bundle_id: BundleId) -> Result<(), StockError<S>> {
        let existing = self.store.bundle_of_op(opid).map_err(StockError::Store)?;
        if let Some(present) = existing.filter(|alt| *alt != bundle_id) {
            return Err(Inconsistency::DistinctBundleOp {
                opid,
                present,
                expected: bundle_id,
            }
            .into());
        }
        // Already recorded (and identical, per the check above): nothing to write.
        if existing.is_some() {
            return Ok(());
        }
        self.store
            .put_op_bundle(opid, bundle_id)
            .map_err(StockError::Store)
    }

    /// Indexes the seals of an operation's assignments: revealed ones by the
    /// outpoint they close, blinded ones by their secret seal. `witness_id` is
    /// `None` for genesis, as [`ExposedSeal::to_output_seal_or`] documents.
    fn index_assignments<Seal: ExposedSeal>(
        &mut self,
        contract_id: ContractId,
        opid: OpId,
        witness_id: Option<Txid>,
        assignments: &Assignments<Seal>,
    ) -> Result<(), StockError<S>> {
        for (type_id, typed) in assignments.iter() {
            match typed {
                TypedAssigns::Declarative(assigns) => {
                    self.index_assigns(contract_id, opid, *type_id, witness_id, assigns)?
                }
                TypedAssigns::Fungible(assigns) => {
                    self.index_assigns(contract_id, opid, *type_id, witness_id, assigns)?
                }
                TypedAssigns::Structured(assigns) => {
                    self.index_assigns(contract_id, opid, *type_id, witness_id, assigns)?
                }
            }
        }
        Ok(())
    }

    /// Indexes one type's assignment vector by outpoint or secret seal.
    ///
    /// The `Opout` each assignment is filed under is not chosen here: its `no`
    /// is the assignment's position in `assignments`, which must be exactly
    /// that [`AssignmentType`]'s vector as it appears on the operation that
    /// produced `opid`, in that order and unfiltered. A re-ordered or filtered
    /// slice would silently misfile the index under the wrong `Opout`.
    fn index_assigns<Seal: ExposedSeal, State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        opid: OpId,
        type_id: AssignmentType,
        witness_id: Option<Txid>,
        assignments: &[Assign<State, Seal>],
    ) -> Result<(), StockError<S>> {
        if !self
            .store
            .contract_registered(contract_id)
            .map_err(StockError::Store)?
        {
            return Err(Inconsistency::ContractAbsent(contract_id).into());
        }
        // `no` is the index in this type's assignment vector (`Opout::no`)
        for (no, assign) in assignments.iter().enumerate() {
            let opout = Opout::new(opid, type_id, no as u16);
            match &assign.seal {
                BuilderSeal::Revealed(seal) => {
                    let outpoint = seal.to_output_seal_or(witness_id).to_outpoint();
                    self.store
                        .put_outpoint_opout(contract_id, outpoint, opout)
                        .map_err(StockError::Store)?;
                }
                BuilderSeal::Concealed(seal) => {
                    self.store
                        .put_secret_opout(contract_id, *seal, opout)
                        .map_err(StockError::Store)?;
                }
            }
        }
        Ok(())
    }

    /// Opouts the contract assigns to each of `outputs`, keyed by the output.
    ///
    /// Lenient, like [`Self::opouts_by_secrets`]: an output this contract
    /// assigns nothing to is absent from the map rather than reported. A caller
    /// asking whether an outpoint carries state cannot know the answer before
    /// it asks, which is why it is asking - a bitcoin-only input added to pay
    /// fees is a fair thing to ask about, and not an inconsistency.
    ///
    /// A caller for which an empty answer *is* an error says so itself, and can
    /// name the output it was: see [`Stock::consign`], where an output naming
    /// no state is a terminal that cannot be built.
    fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeMap<Outpoint, BTreeSet<Opout>>, StockError<S>> {
        if !self
            .store
            .contract_registered(contract_id)
            .map_err(StockError::Store)?
        {
            return Err(Inconsistency::ContractAbsent(contract_id).into());
        }
        let outputs: BTreeSet<Outpoint> = outputs.into_iter().map(Into::into).collect();
        if outputs.is_empty() {
            return Ok(BTreeMap::new());
        }
        self.store
            .opouts_at(contract_id, &outputs)
            .map_err(StockError::Store)
    }

    /// Opouts the contract assigns to any of `secrets`.
    ///
    /// Deliberately lenient, unlike [`Self::opouts_by_outputs`]: a secret this
    /// contract assigns nothing to is skipped rather than reported, since the
    /// caller cannot tell whose contract a blinded seal belongs to before
    /// looking it up.
    fn opouts_by_secrets(
        &self,
        contract_id: ContractId,
        secrets: impl IntoIterator<Item = SecretSeal>,
    ) -> Result<BTreeSet<Opout>, StockError<S>> {
        let secrets: BTreeSet<SecretSeal> = secrets.into_iter().collect();
        self.store
            .opouts_by_secrets(contract_id, &secrets)
            .map_err(StockError::Store)
    }

    fn bundle_id_for_op(&self, opid: OpId) -> Result<BundleId, StockError<S>> {
        self.store
            .bundle_of_op(opid)
            .map_err(StockError::Store)?
            .ok_or_else(|| Inconsistency::OpBundleAbsent(opid).into())
    }

    /// Whether any witness anchoring the bundle is currently valid.
    fn bundle_has_valid_witness(&self, bundle_id: BundleId) -> Result<bool, StockError<S>> {
        let witness_ids = self
            .store
            .bundle_witnesses(bundle_id)
            .map_err(StockError::Store)?;
        if witness_ids.is_empty() {
            return Err(Inconsistency::BundleWitnessUnknown(bundle_id).into());
        }
        let ords = self
            .store
            .witness_ords(&witness_ids)
            .map_err(StockError::Store)?;
        Ok(ords.values().any(|ord| ord.is_valid()))
    }

    fn bundle_info(
        &self,
        bundle_id: BundleId,
    ) -> Result<(BTreeSet<Txid>, ContractId), StockError<S>> {
        let witnesses = self
            .store
            .bundle_witnesses(bundle_id)
            .map_err(StockError::Store)?;
        if witnesses.is_empty() {
            return Err(Inconsistency::BundleWitnessUnknown(bundle_id).into());
        }
        let contract_id = self
            .store
            .bundle_contract(bundle_id)
            .map_err(StockError::Store)?
            .ok_or(Inconsistency::BundleContractUnknown(bundle_id))?;
        Ok((witnesses, contract_id))
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod test {
    use std::convert::Infallible;
    use std::panic;

    use amplify::confinement::{NonEmptyOrdMap, NonEmptyOrdSet, NonEmptyVec};
    use amplify::ByteArray;
    use rgb::assignments::AssignVec;
    use rgb::bitcoin::{absolute, transaction, OutPoint as Outpoint};
    use rgb::commit_verify::mpc::{self, MerkleBlock, MerkleTree, MultiSource};
    use rgb::commit_verify::TryCommitVerify;
    use rgb::txout::BlindSeal;
    use rgb::validation::DbcProof;
    use rgb::vm::WitnessOrd;
    use rgb::{
        AssignRights, AssignmentType, Assignments, BundleId, ContractId, Genesis, GenesisSeal,
        Inputs, KnownTransition, OpId, Operation, Opout, Schema, Transition, TransitionBundle,
        Txid, TypedAssigns, VoidState,
    };
    use strict_encoding::StrictDumb;

    use super::*;
    #[cfg(all(feature = "fs", feature = "serde"))]
    use crate::containers::test_fixtures::almost_default_schema_definition;
    use crate::containers::SealWitness;
    #[cfg(all(feature = "fs", feature = "serde"))]
    use crate::containers::{ConsignmentExt, ValidTransfer};
    #[cfg(all(feature = "fs", feature = "serde"))]
    use crate::contract::resolver::DumbResolver;
    use crate::persistence::sqlite::{SqliteStock, SqliteStore};

    /// Resolver answering with a fixed ord for every witness it is asked about.
    struct FixedResolver(WitnessOrd);
    impl ResolveWitness for FixedResolver {
        fn resolve_witness(&self, _: Txid) -> Result<WitnessStatus, WitnessResolverError> {
            Ok(WitnessStatus::Resolved(tx(0xAA), self.0))
        }
        fn check_chain_net(&self, _: ChainNet) -> Result<(), WitnessResolverError> { Ok(()) }
    }

    fn seed_bundle(store: &mut SqliteStore) -> BundleId {
        let bundle = rgb::TransitionBundle::strict_dumb();
        let bundle_id = bundle.bundle_id();
        store.put_bundle(&bundle).unwrap();
        bundle_id
    }

    fn seed_witness(store: &mut SqliteStore) -> Txid {
        let witness = SealWitness::strict_dumb();
        let witness_id = witness.witness_id();
        store.put_witness(&witness).unwrap();
        witness_id
    }

    fn seed_contract(store: &mut SqliteStore) -> ContractId {
        let schema = Schema::strict_dumb();
        store.put_schema(&schema).unwrap();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        store.put_genesis(&genesis).unwrap();
        contract_id
    }

    #[test]
    fn index_tracks_bundles_and_assignments() {
        let mut stock = SqliteStock::in_memory().unwrap();

        let contract_id = seed_contract(&mut stock.store);
        let other_contract = ContractId::from_byte_array([0xCA; 32]);
        let bundle_id = seed_bundle(&mut stock.store);
        let witness_id = seed_witness(&mut stock.store);
        let opid = OpId::strict_dumb();

        // registering the same (bundle, witness, contract) twice is idempotent
        stock
            .register_bundle(bundle_id, witness_id, contract_id)
            .unwrap();
        stock
            .register_bundle(bundle_id, witness_id, contract_id)
            .unwrap();
        assert!(matches!(
            stock.register_bundle(bundle_id, witness_id, other_contract),
            Err(StockError::Inconsistency(Inconsistency::DistinctBundleContract { .. }))
        ));
        let (witnesses, found_contract) = stock.bundle_info(bundle_id).unwrap();
        assert_eq!(witnesses, bset![witness_id]);
        assert_eq!(found_contract, contract_id);

        stock.register_operation(opid, bundle_id).unwrap();
        stock.register_operation(opid, bundle_id).unwrap();
        assert_eq!(stock.bundle_id_for_op(opid).unwrap(), bundle_id);
        // an operation belongs to one bundle: a second one is an inconsistency,
        // not a silent replacement or a silent no-op
        let other_bundle = BundleId::from_byte_array([0xCB; 32]);
        assert!(matches!(
            stock.register_operation(opid, other_bundle),
            Err(StockError::Inconsistency(Inconsistency::DistinctBundleOp { .. }))
        ));
        assert_eq!(stock.bundle_id_for_op(opid).unwrap(), bundle_id);

        let spent = Opout::new(opid, AssignmentType::strict_dumb(), 0);
        let spender = OpId::from([0xCC; 32]);
        stock.store.put_op_input(spent, spender, bundle_id).unwrap();
        stock.store.put_op_input(spent, spender, bundle_id).unwrap();
        assert_eq!(stock.store.child_bundles_of_op(opid).unwrap().len(), 1);
        assert_eq!(stock.store.child_ops_of_op(opid).unwrap(), bset![(spender, bundle_id)]);

        let seal = GenesisSeal::strict_dumb();
        let assignments = [Assign::revealed(seal, VoidState::strict_dumb())];
        let type_id = AssignmentType::strict_dumb();
        stock
            .index_assigns(contract_id, opid, type_id, None, &assignments)
            .unwrap();
        let outpoint = seal.to_output_seal().unwrap().to_outpoint();
        let opouts = stock.opouts_by_outputs(contract_id, [outpoint]).unwrap();
        assert_eq!(opouts, bmap! { outpoint => bset![Opout::new(opid, type_id, 0)] });
        let assigning = stock
            .contracts_assigning([outpoint])
            .unwrap()
            .collect::<BTreeSet<_>>();
        assert_eq!(assigning, bset![contract_id]);
        // an outpoint the contract assigns nothing to is absent from the map,
        // not an error: a caller asking whether state is there cannot know
        // before it asks
        let unknown = Outpoint::new(Txid::strict_dumb(), 0xbeef);
        assert!(stock
            .opouts_by_outputs(contract_id, [unknown])
            .unwrap()
            .is_empty());
    }

    /// The strictness that used to live in the lookup: composing for an output
    /// the contract assigns nothing to is still an error, because the terminal
    /// asked for cannot be built over state which is not there.
    #[test]
    fn consign_rejects_an_output_with_no_state() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let contract_id = seed_consign_contract(&mut stock);

        let unknown = OutputSeal::with(Txid::strict_dumb(), 0xbeefu32);
        assert!(matches!(
            stock.transfer(contract_id, [unknown], [], [], None, None),
            Err(StockError::Inconsistency(Inconsistency::OutpointUnknown(..)))
        ));
    }

    /// The genesis row is a contract's registration and there is no second one:
    /// an index row naming a contract the store does not hold is refused by the
    /// foreign key rather than kept as a dangling reference.
    #[test]
    fn index_rows_need_the_contract_genesis() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let unknown = ContractId::from_byte_array([0xCA; 32]);
        assert!(!stock.store.contract_registered(unknown).unwrap());

        let outpoint = Outpoint::new(Txid::strict_dumb(), 0);
        let opout = Opout::new(OpId::strict_dumb(), AssignmentType::strict_dumb(), 0);
        assert!(stock
            .store
            .put_outpoint_opout(unknown, outpoint, opout)
            .is_err());

        // storing the genesis is all it takes for the same write to be accepted
        let contract_id = seed_contract(&mut stock.store);
        assert!(stock.store.contract_registered(contract_id).unwrap());
        stock
            .store
            .put_outpoint_opout(contract_id, outpoint, opout)
            .unwrap();
    }

    /// A blinded seal is a UTXO plus a blinding factor, bound to no contract:
    /// nothing stops the same secret from being assigned under two contracts.
    /// The secret->opout index is therefore contract-scoped, exactly like its
    /// outpoint->opout twin, so composing a consignment for one contract cannot
    /// seed itself with another contract's operations.
    #[test]
    fn secret_seal_index_is_contract_scoped() {
        let mut stock = SqliteStock::in_memory().unwrap();

        let contract_id = seed_contract(&mut stock.store);
        let other_contract = ContractId::from_byte_array([0xCA; 32]);

        let secret = SecretSeal::from([0x42; 32]);
        let opid = OpId::strict_dumb();
        let type_id = AssignmentType::strict_dumb();
        let assignments: [Assign<VoidState, GenesisSeal>; 1] =
            [Assign::with(BuilderSeal::Concealed(secret), VoidState::strict_dumb())];
        stock
            .index_assigns(contract_id, opid, type_id, None, &assignments)
            .unwrap();

        assert_eq!(stock.opouts_by_secrets(contract_id, [secret]).unwrap(), bset![Opout::new(
            opid, type_id, 0
        )]);
        // the same secret, looked up under a contract which never assigned it
        assert!(stock
            .opouts_by_secrets(other_contract, [secret])
            .unwrap()
            .is_empty());
        // an unknown secret is not an inconsistency, just an empty answer
        assert!(stock
            .opouts_by_secrets(contract_id, [SecretSeal::from([0xFF; 32])])
            .unwrap()
            .is_empty());
    }

    /// Two transitions spending the same opout - what a store holds while a
    /// reorg has not yet settled which of them stands - must both be indexed as
    /// children of the operation producing it. Single-use seals make the
    /// conflict resolvable, not unrepresentable: dropping either edge hides a
    /// whole subtree from `set_ops_as_invalid` and `maybe_update_ops_as_valid`,
    /// which reach it only through this index.
    #[test]
    fn conflicting_spenders_of_one_opout_are_both_indexed() {
        let mut stock = SqliteStock::in_memory().unwrap();

        let contract_id = seed_contract(&mut stock.store);
        let witness_id = seed_witness(&mut stock.store);
        let parent = OpId::from([0xAB; 32]);
        let spent = Opout::new(parent, AssignmentType::strict_dumb(), 0);

        let mut children = vec![];
        for nonce in [0u64, 1] {
            let mut transition = Transition::strict_dumb();
            transition.inputs = Inputs::from(NonEmptyOrdSet::with(spent));
            // the two spenders differ, as two candidate spends of one seal do
            transition.nonce = nonce;
            let opid = transition.id();
            let bundle = TransitionBundle {
                input_map: NonEmptyOrdMap::from_checked(bmap! { spent => opid }),
                known_transitions: NonEmptyVec::with(KnownTransition::new(opid, transition)),
            };
            let bundle_id = bundle.bundle_id();
            stock.consume_bundle(bundle.clone(), bundle_id).unwrap();
            stock
                .index_bundle(contract_id, &bundle, witness_id, bundle_id)
                .unwrap();
            children.push((opid, bundle_id));
        }
        assert_ne!(children[0], children[1]);

        // forward: both bundles are children of the operation they spend from
        let indexed = stock.store.child_bundles_of_op(parent).unwrap();
        assert_eq!(indexed, children.iter().map(|(_, id)| *id).collect::<BTreeSet<_>>());
        assert_eq!(
            stock
                .op_children(parent)
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            children.iter().copied().collect::<BTreeSet<_>>()
        );

        // backward: each spender still reports the opout it consumes
        for (opid, _) in &children {
            assert_eq!(stock.store.input_opouts_for_op(*opid).unwrap(), bset![spent]);
        }
    }

    #[test]
    fn witness_ord_and_invalid_ops_persist() {
        let mut stock = SqliteStock::in_memory().unwrap();

        let witness_id = seed_witness(&mut stock.store);
        assert_eq!(stock.store.witness_ord(witness_id).unwrap(), None);
        stock
            .store_transaction(|s| s.set_witness_ord(witness_id, WitnessOrd::Archived))
            .unwrap();
        assert_eq!(stock.store.witness_ord(witness_id).unwrap(), Some(WitnessOrd::Archived));
        assert_eq!(stock.store.all_witness_ords().unwrap().len(), 1);

        let opid = OpId::strict_dumb();
        assert!(!stock.all_invalid_op_ids().unwrap().contains(&opid));
        stock
            .store_transaction(|s| s.update_op(opid, false))
            .unwrap();
        assert!(stock.all_invalid_op_ids().unwrap().contains(&opid));
        stock
            .store_transaction(|s| s.update_op(opid, true))
            .unwrap();
        assert!(!stock.all_invalid_op_ids().unwrap().contains(&opid));
    }

    #[test]
    fn store_transaction_rollback_discards_writes() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let schema = Schema::strict_dumb();
        let schema_id = schema.schema_id();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema_id;
        let contract_id = genesis.contract_id();

        let err = stock.store_transaction::<(), Inconsistency>(|s| {
            s.store.put_schema(&schema).map_err(StockError::Store)?;
            s.store.put_genesis(&genesis).map_err(StockError::Store)?;
            Err(StockError::Inconsistency(Inconsistency::SchemaAbsent(schema_id)))
        });
        assert!(matches!(err, Err(StockError::Inconsistency(Inconsistency::SchemaAbsent(_)))));
        assert!(matches!(
            stock.load_schema(schema_id),
            Err(StockError::Inconsistency(Inconsistency::SchemaAbsent(_)))
        ));
        assert!(!stock.store.contract_registered(contract_id).unwrap());
    }

    /// A stock may be handed to another thread, and read from several at once:
    /// its accessors take `&self`, while everything which writes takes `&mut
    /// self` and is therefore excluded while any read is in flight.
    #[test]
    fn stock_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SqliteStock>();
        assert_send_sync::<ContractStateSnapshot>();
    }

    /// Store transactions do not nest: an inner one would commit the outer unit
    /// of work half-way through, leaving the rest of it to run - and to fail -
    /// with nothing to roll back. The nesting is refused instead, and the outer
    /// transaction rolls back like on any other error.
    #[test]
    fn nested_store_transaction_is_refused() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let schema = Schema::strict_dumb();
        let schema_id = schema.schema_id();
        let witness_id = seed_witness(&mut stock.store);

        let err = stock.store_transaction(|s| {
            s.store.put_schema(&schema).map_err(StockError::Store)?;
            // a public mutator: it opens a transaction of its own
            s.upsert_witness(witness_id, WitnessOrd::Archived)
        });
        assert!(matches!(err, Err(StockError::NestedTransaction)));

        // the write made before the nested call is rolled back, and the nested
        // one never happened
        assert!(matches!(
            stock.load_schema(schema_id),
            Err(StockError::Inconsistency(Inconsistency::SchemaAbsent(_)))
        ));
        assert_eq!(stock.store.witness_ord(witness_id).unwrap(), None);
    }

    /// A panic unwinding out of a unit of work must not leave its transaction
    /// open: the store goes on being used, and a leaked transaction would be
    /// committed by whatever runs next - carrying the partial writes of the
    /// panicking one with it.
    #[test]
    fn panic_inside_store_transaction_rolls_back() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let schema = Schema::strict_dumb();
        let schema_id = schema.schema_id();
        let witness_id = seed_witness(&mut stock.store);

        let hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let res = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            stock.store_transaction::<(), Infallible>(|s| {
                s.store.put_schema(&schema).map_err(StockError::Store)?;
                panic!("mid-transaction")
            })
        }));
        panic::set_hook(hook);
        assert!(res.is_err(), "the panic must propagate");

        // the write the panicking unit of work made is rolled back
        assert!(matches!(
            stock.load_schema(schema_id),
            Err(StockError::Inconsistency(Inconsistency::SchemaAbsent(_)))
        ));

        // and nothing is left open: the next unit of work opens a transaction
        // of its own instead of being refused as a nested one
        stock
            .store_transaction(|s| s.set_witness_ord(witness_id, WitnessOrd::Archived))
            .unwrap();
        assert_eq!(stock.store.witness_ord(witness_id).unwrap(), Some(WitnessOrd::Archived));
    }

    #[test]
    fn stale_consignment_stores_what_it_learned() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let contract_id = seed_consign_contract(&mut stock);
        let genesis = stock.genesis(contract_id).unwrap();

        // a transfer carrying a single bundle, closed by a single witness
        let witness_nonce = 0xAA;
        let witness_id = txid(witness_nonce);
        let bundle = seal_bundle(contract_id, &[GraphSeal::new_random_vout(1u32)], 0);
        let bundle_id = bundle.bundle_id();
        let opids = bundle.known_transitions_opids();
        let anchor = Anchor::new(
            mpc_merkle_block(contract_id, bundle_id)
                .to_merkle_proof(contract_id.into())
                .unwrap(),
            DbcProof::strict_dumb(),
        );
        let transfer = Consignment::<true> {
            version: ConsignmentVer::V1,
            transfer: true,
            terminals: none!(),
            genesis,
            bundles: Confined::from_checked(vec![WitnessBundle::with(
                tx(witness_nonce),
                anchor,
                bundle,
            )]),
        };
        let valid = |c: &Consignment<true>| {
            ValidTransfer::from_parts(c.clone(), rgb::validation::Status::default())
        };

        stock
            .accept_transfer(valid(&transfer), FixedResolver(WitnessOrd::Tentative))
            .expect("a transfer with a valid witness is accepted");

        // the same transfer, now with its witness archived by a reorg
        assert!(matches!(
            stock.accept_transfer(valid(&transfer), FixedResolver(WitnessOrd::Archived)),
            Err(StockError::AbsentValidWitness)
        ));
        assert_eq!(
            stock.store.witness_ord(witness_id).unwrap(),
            Some(WitnessOrd::Archived),
            "the fresh ord of an already-known witness must be stored"
        );
        assert_eq!(
            stock.all_invalid_op_ids().unwrap(),
            opids,
            "the operations of the bundle left without a valid witness must be invalidated"
        );
    }

    #[cfg(all(feature = "fs", feature = "serde"))]
    #[test]
    fn accept_transfer_exposes_indexed_contract() {
        let valid_transfer =
            ValidTransfer::load_file("asset/valid_transfer.default").expect("load fixture");
        let contract_id = valid_transfer.contract_id();
        let schema_id = valid_transfer.schema_id();

        let mut stock = SqliteStock::in_memory().unwrap();
        // a v1 consignment carries only its schema id, so the schema definition
        // must have been imported out-of-band
        stock
            .import_schema_definition(almost_default_schema_definition())
            .unwrap();
        stock
            .accept_transfer(valid_transfer, DumbResolver)
            .expect("accept_transfer must persist under the foreign keys");

        assert_eq!(stock.schema(schema_id).unwrap().schema_id(), schema_id);
        assert_eq!(stock.contract_state(contract_id).unwrap().contract_id(), contract_id);
        assert_eq!(stock.contract_info(contract_id).unwrap().id, contract_id);
    }

    /// The descendant guard in `maybe_update_ops_as_valid` makes sure that a
    /// subtree reachable through multiple revalidated parents is walked only
    /// once. With a chain of k diamonds (op splitting to two ops merging back
    /// into one) the unguarded walk visits the tail of the chain O(2^k)
    /// times: with k = 64 it never terminates, so a removed guard shows up
    /// here as a watchdog timeout.
    #[test]
    fn maybe_update_ops_as_valid_diamond_chain() {
        use std::sync::mpsc;
        use std::time::Duration;

        const DIAMONDS: usize = 64;

        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut stock = SqliteStock::in_memory().unwrap();
            let contract_id = seed_contract(&mut stock.store);
            let witness_id = seed_witness(&mut stock.store);
            // the walk asks the store whether a bundle still has a valid
            // witness, so the one anchoring every bundle here needs an ord
            stock
                .store
                .put_witness_ord(witness_id, WitnessOrd::Tentative)
                .unwrap();
            let ty = AssignmentType::strict_dumb();

            let make_op = |parents: &[OpId], nonce: u64| -> Transition {
                let mut transition = Transition::strict_dumb();
                if !parents.is_empty() {
                    transition.inputs = Inputs::from(NonEmptyOrdSet::from_checked(
                        parents.iter().map(|p| Opout::new(*p, ty, 0)).collect(),
                    ));
                }
                transition.nonce = nonce;
                transition
            };

            let mut all_opids = bset![];
            let mut register = |stock: &mut Stock<SqliteStore>,
                                transition: Transition|
             -> (OpId, BundleId) {
                let opid = transition.id();
                let input_map = NonEmptyOrdMap::from_checked(
                    transition
                        .inputs
                        .iter()
                        .map(|input| (*input, opid))
                        .collect(),
                );
                let bundle = TransitionBundle {
                    input_map,
                    known_transitions: NonEmptyVec::with(KnownTransition::new(opid, transition)),
                };
                let bundle_id = bundle.bundle_id();
                stock.consume_bundle(bundle.clone(), bundle_id).unwrap();
                stock
                    .index_bundle(contract_id, &bundle, witness_id, bundle_id)
                    .unwrap();
                // everything starts as invalid
                stock.update_op(opid, false).unwrap();
                all_opids.insert(opid);
                (opid, bundle_id)
            };

            // root op; its dumb input plays the role of genesis
            let (root_opid, root_bundle_id) = register(&mut stock, make_op(&[], 0));
            let mut prev = root_opid;
            for _ in 0..DIAMONDS {
                let (left, _) = register(&mut stock, make_op(&[prev], 1));
                let (right, _) = register(&mut stock, make_op(&[prev], 2));
                let (join, _) = register(&mut stock, make_op(&[left, right], 0));
                prev = join;
            }

            // revalidate the whole graph starting from the root, as if all
            // the witnesses became valid again
            let mut invalid_ops = stock.all_invalid_op_ids().unwrap();
            let mut maybe_became_valid_opids = all_opids;
            let valid = stock
                .maybe_update_ops_as_valid(
                    root_opid,
                    root_bundle_id,
                    &mut invalid_ops,
                    &mut maybe_became_valid_opids,
                )
                .unwrap();

            assert!(valid);
            assert!(stock.all_invalid_op_ids().unwrap().is_empty());
            tx.send(()).unwrap();
        });

        match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(()) => handle.join().unwrap(),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("revalidation did not terminate: descendant guard not working")
            }
            // the worker thread panicked: propagate its panic
            Err(mpsc::RecvTimeoutError::Disconnected) => handle.join().unwrap(),
        }
    }

    //////////////////////////////////////////////////////////////
    // Stock::consign tests
    //////////////////////////////////////////////////////////////

    /// An empty transaction, made unique by `nonce`
    fn tx(nonce: u8) -> Tx {
        Tx {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(nonce as u32),
            input: vec![],
            output: vec![],
        }
    }

    /// The id of the transaction identified by `nonce`
    fn txid(nonce: u8) -> Txid { tx(nonce).compute_txid() }

    /// Seeds a dumb schema and its genesis, so that the consignment can be assembled.
    fn seed_consign_contract(stock: &mut SqliteStock) -> ContractId {
        let schema = Schema::strict_dumb();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        stock.store.put_schema(&schema).unwrap();
        stock.store.put_genesis(&genesis).unwrap();
        contract_id
    }

    /// The `mpc::MerkleBlock` committing `bundle_id` under `contract_id`
    fn mpc_merkle_block(contract_id: ContractId, bundle_id: BundleId) -> MerkleBlock {
        MerkleBlock::from(
            MerkleTree::try_commit(&MultiSource {
                min_depth: amplify::num::u5::ZERO,
                messages: Confined::from_checked(bmap! {
                    mpc::ProtocolId::from_byte_array(contract_id.to_byte_array()) =>
                        mpc::Message::from_byte_array(bundle_id.to_byte_array())
                }),
                static_entropy: None,
            })
            .unwrap(),
        )
    }

    /// A bundle holding a single transition which spends genesis' `input_no` and
    /// assigns state to each of `seals`
    fn seal_bundle(
        contract_id: ContractId,
        seals: &[GraphSeal],
        input_no: u16,
    ) -> TransitionBundle {
        let ty = AssignmentType::strict_dumb();
        let mut transition = Transition::strict_dumb();
        transition.inputs = Inputs::from(NonEmptyOrdSet::with(Opout::new(
            OpId::from_byte_array(contract_id.to_byte_array()),
            ty,
            input_no,
        )));
        transition.assignments = Assignments::from(Confined::from_checked(bmap! {
            ty => TypedAssigns::Declarative(AssignVec::with(NonEmptyVec::from_checked(
                seals
                    .iter()
                    .map(|seal| AssignRights::revealed(*seal, VoidState::default()))
                    .collect(),
            )))
        }));
        let opid = transition.id();
        TransitionBundle {
            input_map: NonEmptyOrdMap::from_checked(
                transition.inputs.iter().map(|i| (*i, opid)).collect(),
            ),
            known_transitions: NonEmptyVec::with(KnownTransition::new(opid, transition)),
        }
    }

    /// A witness anchoring bundle_id, closed by the transaction identified by `nonce`
    fn seal_witness(contract_id: ContractId, bundle_id: BundleId, nonce: u8) -> SealWitness {
        SealWitness::new(
            tx(nonce),
            mpc_merkle_block(contract_id, bundle_id),
            DbcProof::strict_dumb(),
            None,
        )
    }

    /// Persists `bundle` as anchored to the transaction identified by `nonce`
    /// The same bundle consumed under two witnesses, the way a Lightning node
    /// stores one bundle under each commitment transaction carrying it. Its
    /// seal on the witness transaction is listed under both, whichever of the
    /// two was consumed last, and stays reachable at both outpoints, until one
    /// of them is archived and only the other is left.
    #[test]
    fn witness_seal_resolves_against_every_witness() {
        let mined = WitnessOrd::Mined(
            rgb::vm::WitnessPos::bitcoin(NonZeroU32::new(100).unwrap(), 1231006505).unwrap(),
        );
        // the first witness mined covers the first one consumed being the one
        // that stands, which a last-write-wins store gets wrong
        for (mined_nonce, ignored_nonce) in [(1u8, 2u8), (2, 1)] {
            let mut stock = SqliteStock::in_memory().unwrap();
            let contract_id = seed_consign_contract(&mut stock);
            let vout = 1u32;
            let bundle = seal_bundle(contract_id, &[GraphSeal::new_random_vout(vout)], 0);
            let bundle_id = bundle.bundle_id();
            let transition = &bundle.known_transitions.first().unwrap().transition;
            for nonce in [1u8, 2] {
                seed_witness_bundle(&mut stock, contract_id, nonce, bundle.clone());
                stock
                    .add_transition(contract_id, transition, txid(nonce), bundle_id)
                    .unwrap();
            }
            stock.upsert_witness(txid(mined_nonce), mined).unwrap();
            stock
                .upsert_witness(txid(ignored_nonce), WitnessOrd::Ignored)
                .unwrap();

            let at = |stock: &SqliteStock, nonce: u8| {
                stock
                    .contract_assignments_for(contract_id, [Outpoint::new(txid(nonce), vout)])
                    .unwrap()
                    .remove(&OutputSeal::with(txid(nonce), vout))
                    .map_or(0, |by_opout| by_opout.len())
            };
            let allocations = |stock: &SqliteStock| {
                stock
                    .allocations::<VoidState>(contract_id, AllocationFilter::all(Visibility::Valid))
                    .unwrap()
            };

            let listed = |stock: &SqliteStock| {
                allocations(stock)
                    .into_iter()
                    .map(|a| (a.seal, a.witness))
                    .collect::<BTreeSet<_>>()
            };
            let under = |nonce: u8| (OutputSeal::with(txid(nonce), vout), Some(txid(nonce)));
            assert_eq!(
                listed(&stock),
                bset![under(mined_nonce), under(ignored_nonce)],
                "listed once per witness that is not archived (mined {mined_nonce})"
            );
            assert_eq!(at(&stock, mined_nonce), 1, "reachable at the mined witness");
            assert_eq!(at(&stock, ignored_nonce), 1, "and at the ignored one, which may yet be");

            // the ignored witness is replaced for good: its outpoint no longer
            // exists, and the mined one is unaffected
            stock
                .upsert_witness(txid(ignored_nonce), WitnessOrd::Archived)
                .unwrap();
            assert_eq!(at(&stock, ignored_nonce), 0, "nothing lands on an archived witness");
            assert_eq!(at(&stock, mined_nonce), 1);
            assert_eq!(listed(&stock), bset![under(mined_nonce)]);
        }
    }

    fn seed_witness_bundle(
        stock: &mut SqliteStock,
        contract_id: ContractId,
        nonce: u8,
        bundle: TransitionBundle,
    ) -> BundleId {
        let witness_id = txid(nonce);
        let bundle_id = bundle.bundle_id();
        stock
            .consume_witness(&seal_witness(contract_id, bundle_id, nonce))
            .unwrap();
        stock
            .upsert_witness(witness_id, WitnessOrd::Tentative)
            .unwrap();
        stock.consume_bundle(bundle.clone(), bundle_id).unwrap();
        stock
            .index_bundle(contract_id, &bundle, witness_id, bundle_id)
            .unwrap();
        bundle_id
    }

    /// Test cases for construction of consignment terminals. Returns:
    /// - Vec of seals to include in stock
    /// - Vec of OutputSeal to input to the consign method
    /// - Vec of expected seals to be included as terminals
    ///
    /// 4 cases are covered
    /// - regular "pay to witness", requested as terminal
    /// - change output in "pay to witness", not requested as terminal
    /// - revealed "pay to utxo" with the same vout as one of the above, not requested as terminal
    /// - revealed "pay to utxo", requested as terminal
    fn terminal_seal_cases(witness_id: Txid) -> (Vec<GraphSeal>, Vec<OutputSeal>, Vec<GraphSeal>) {
        let requested_vout = 1u32;
        let other_txid = txid(0xBB);
        let utxo_txid = txid(0xCC);

        let witness_beneficiary = GraphSeal::new_random_vout(requested_vout);
        let witness_change = GraphSeal::new_random_vout(2u32);
        let colliding_change: GraphSeal =
            BlindSeal::new_random(other_txid, requested_vout).transmutate();
        let utxo_beneficiary: GraphSeal = BlindSeal::new_random(utxo_txid, 0u32).transmutate();

        // an unrequested seal comes first on purpose: whoever scans the assignments has to keep
        // going past it rather than concluding from the first one alone
        let seals = vec![witness_change, witness_beneficiary, colliding_change, utxo_beneficiary];
        let outputs =
            vec![OutputSeal::with(witness_id, requested_vout), OutputSeal::with(utxo_txid, 0u32)];
        let expected = vec![witness_beneficiary, utxo_beneficiary];
        (seals, outputs, expected)
    }

    /// Apply terminal_seal_cases to stock.transfer
    #[test]
    fn terminal_seals_from_stored_bundle() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let contract_id = seed_consign_contract(&mut stock);

        let witness_nonce = 0xAA;
        let witness_id = txid(witness_nonce);
        let (seals, outputs, expected) = terminal_seal_cases(witness_id);
        let bundle_id = seed_witness_bundle(
            &mut stock,
            contract_id,
            witness_nonce,
            seal_bundle(contract_id, &seals, 0),
        );

        let (consignment, _) = stock
            .transfer(contract_id, outputs, [], [], Some(witness_id), None)
            .expect("consignment should be built");

        assert_eq!(consignment.terminals.len(), 1);
        let terminals = consignment
            .terminals
            .get(&bundle_id)
            .expect("the bundle must be a terminal")
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            terminals,
            expected
                .into_iter()
                .map(BuilderSeal::Revealed)
                .collect::<BTreeSet<_>>()
        );
    }

    /// A fascia bundle out of which nothing is requested cannot yield a
    /// consignment: a bundle holds at least one transition. Requesting nothing
    /// at all, or only seals the bundle does not pay to, must be reported
    /// rather than panic while confining the empty selection.
    #[test]
    fn fascia_with_no_requested_transition() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let contract_id = seed_consign_contract(&mut stock);

        let witness_nonce = 0xAA;
        let seal = GraphSeal::new_random_vout(1u32);
        let bundle = seal_bundle(contract_id, &[seal], 0);
        let bundle_id = bundle.bundle_id();
        let fascia = Fascia::new(
            seal_witness(contract_id, bundle_id, witness_nonce),
            NonEmptyOrdMap::with_key_value(contract_id, bundle),
        );

        // nothing requested at all
        assert!(matches!(
            stock.transfer_from_fascia(contract_id, [], [], [], &fascia, None),
            Err(StockError::InvalidInput(ConsignError::NoRequestedTransition(id)))
                if id == bundle_id
        ));

        // an output the bundle assigns no state to
        let unrelated = OutputSeal::with(txid(0xEE), 0u32);
        assert!(matches!(
            stock.transfer_from_fascia(contract_id, [unrelated], [], [], &fascia, None),
            Err(StockError::InvalidInput(ConsignError::NoRequestedTransition(id)))
                if id == bundle_id
        ));
    }

    /// Two stocks over the same database file are two connections, which is
    /// how concurrency is meant to be had: one owns its store exclusively, and
    /// what it commits the other sees at once, because a reader reads through
    /// to the store instead of answering from a copy taken when it was made.
    ///
    /// Holding a reader while mutating the *same* stock needs no test: the
    /// reader borrows the stock, so the compiler rejects it.
    #[test]
    fn one_connection_sees_what_another_commits() {
        struct TentativeResolver;
        impl WitnessOrdProvider for TentativeResolver {
            fn witness_ord(&self, _: Txid) -> Result<WitnessOrd, WitnessResolverError> {
                Ok(WitnessOrd::Tentative)
            }
        }

        let path = std::env::temp_dir().join(format!("rgb-stock-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut writer = SqliteStock::open(&path).unwrap();
        let contract_id = seed_consign_contract(&mut writer);

        let witness_nonce = 0xAA;
        let witness_id = txid(witness_nonce);
        let bundle = seal_bundle(contract_id, &[GraphSeal::new_random_vout(1u32)], 0);
        let bundle_id = bundle.bundle_id();
        let fascia = Fascia::new(
            seal_witness(contract_id, bundle_id, witness_nonce),
            NonEmptyOrdMap::with_key_value(contract_id, bundle),
        );
        writer.consume_fascia(fascia, TentativeResolver).unwrap();

        // a second connection, opened after the fact, sees the committed state
        let observer = SqliteStock::open(&path).unwrap();
        let rights = || {
            observer
                .contract_state(contract_id)
                .unwrap()
                .rights_all(None)
                .count()
        };
        assert_eq!(rights(), 1);

        // and it sees what the first commits from now on, without being reopened
        writer
            .upsert_witness(witness_id, WitnessOrd::Archived)
            .unwrap();
        assert_eq!(rights(), 0, "an archived witness must hide the state it witnesses");

        writer
            .upsert_witness(witness_id, WitnessOrd::Tentative)
            .unwrap();
        assert_eq!(rights(), 1, "and the state must come back when it is no longer archived");

        drop((writer, observer));
        let _ = std::fs::remove_file(&path);
    }

    /// Two connections which both want to write are serialized, not
    /// interleaved: the second one's unit of work does not begin until the
    /// first has committed. That is what lets a unit of work read and then
    /// write inside its transaction without another writer invalidating what it
    /// read in between.
    #[test]
    fn writers_are_serialized_across_connections() {
        let path = std::env::temp_dir().join(format!("rgb-writers-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut writer = SqliteStock::open(&path).unwrap();

        let transaction = StoreTransaction::open(&mut writer).unwrap().unwrap();

        let other_path = path.clone();
        let other = std::thread::spawn(move || {
            let mut other = SqliteStock::open(&other_path).unwrap();
            other.store_secret_seal(GraphSeal::new_random_vout(1u32))
        });

        // the write lock is held here, so the other connection cannot have got
        // its own unit of work under way
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!other.is_finished(), "a second writer must wait out the first one");

        transaction.commit().unwrap();
        other
            .join()
            .unwrap()
            .expect("the second writer must go through once the first has committed");

        drop(writer);
        let _ = std::fs::remove_file(&path);
    }

    /// Apply terminal_seal_cases to stock.transfer_from_fascia
    #[test]
    fn terminal_seals_from_fascia() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let contract_id = seed_consign_contract(&mut stock);

        let witness_nonce = 0xAA;
        let (seals, outputs, expected) = terminal_seal_cases(txid(witness_nonce));
        let bundle = seal_bundle(contract_id, &seals, 0);
        let bundle_id = bundle.bundle_id();
        let fascia = Fascia::new(
            seal_witness(contract_id, bundle_id, witness_nonce),
            NonEmptyOrdMap::with_key_value(contract_id, bundle),
        );

        let (consignment, _) = stock
            .transfer_from_fascia(contract_id, outputs, [], [], &fascia, None)
            .expect("consignment should be built");

        assert_eq!(consignment.terminals.len(), 1);
        let terminals = consignment
            .terminals
            .get(&bundle_id)
            .expect("the bundle must be a terminal")
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            terminals,
            expected
                .into_iter()
                .map(BuilderSeal::Revealed)
                .collect::<BTreeSet<_>>()
        );
    }

    /// Re-resolving the witnesses of a stock invalidates the operations of a
    /// bundle whose witness is gone, and revalidates them once it is back. Both
    /// directions are one unit of work, with the chain queried before it opens.
    #[test]
    fn update_witnesses_tracks_operation_validity() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let contract_id = seed_consign_contract(&mut stock);

        let witness_nonce = 0xAA;
        let witness_id = txid(witness_nonce);
        let bundle = seal_bundle(contract_id, &[GraphSeal::new_random_vout(1u32)], 0);
        let opids = bundle.known_transitions_opids();
        seed_witness_bundle(&mut stock, contract_id, witness_nonce, bundle);
        assert!(stock.all_invalid_op_ids().unwrap().is_empty());

        // the witness is gone: the operations it witnesses become invalid
        let res = stock
            .update_witnesses(FixedResolver(WitnessOrd::Archived), 0, vec![])
            .unwrap();
        assert_eq!(res.succeeded, 1);
        assert!(res.failed.is_empty());
        assert_eq!(stock.store.witness_ord(witness_id).unwrap(), Some(WitnessOrd::Archived));
        assert_eq!(stock.all_invalid_op_ids().unwrap(), opids);

        // and it is back: so are they
        let res = stock
            .update_witnesses(FixedResolver(WitnessOrd::Tentative), 0, vec![])
            .unwrap();
        assert_eq!(res.succeeded, 1);
        assert_eq!(stock.store.witness_ord(witness_id).unwrap(), Some(WitnessOrd::Tentative));
        assert!(stock.all_invalid_op_ids().unwrap().is_empty());
    }

    /// Test terminal collection in stock.consign_operations
    ///
    /// Each of the three bundles is closed by a different witness TX and all three seals are
    /// requested as outputs, so every seal may only be resolved against the witness of the
    /// bundle holding it: the first two are witness-vout seals sharing a vout on
    /// distinct witnesses, the third sits on a pre-existing UTXO (`TxPtr::Txid`)
    #[test]
    fn terminal_seals_across_multiple_witnesses() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let contract_id = seed_consign_contract(&mut stock);
        let vout = 1u32;

        // two witness beneficiaries sharing a vout, each closed by a different witness TX
        let (witness_1, witness_2) = (0xAA, 0xBB);
        let seal_1 = GraphSeal::new_random_vout(vout);
        let seal_2 = GraphSeal::new_random_vout(vout);
        // and an allocation received on a pre-existing UTXO: explicit txid, not
        // TxPtr::WitnessTx
        let witness_3 = 0xCC;
        let utxo_txid = txid(0xDD);
        let seal_3: GraphSeal = BlindSeal::new_random(utxo_txid, 0u32).transmutate();

        let bundle_1 = seal_bundle(contract_id, &[seal_1], 0);
        let bundle_2 = seal_bundle(contract_id, &[seal_2], 1);
        let bundle_3 = seal_bundle(contract_id, &[seal_3], 2);
        let bundle_1 = seed_witness_bundle(&mut stock, contract_id, witness_1, bundle_1);
        let bundle_2 = seed_witness_bundle(&mut stock, contract_id, witness_2, bundle_2);
        let bundle_3 = seed_witness_bundle(&mut stock, contract_id, witness_3, bundle_3);

        let (consignment, _) = stock
            .transfer(
                contract_id,
                [
                    OutputSeal::with(txid(witness_1), vout),
                    OutputSeal::with(txid(witness_2), vout),
                    OutputSeal::with(utxo_txid, 0u32),
                ],
                [],
                [],
                None,
                None,
            )
            .expect("consignment should be built");

        assert_eq!(consignment.terminals.len(), 3);
        for (bundle_id, seal) in [(bundle_1, seal_1), (bundle_2, seal_2), (bundle_3, seal_3)] {
            let terminals = consignment
                .terminals
                .get(&bundle_id)
                .expect("bundle must be a terminal")
                .into_iter()
                .collect::<BTreeSet<_>>();
            assert_eq!(terminals, bset![BuilderSeal::Revealed(seal)]);
        }
    }

    /// One bundle anchored under two witnesses, the consignment requested for
    /// each of them by witness id: it is carried under the requested one, with
    /// its terminal resolved against it, whichever of the two ranks first.
    #[test]
    fn consignment_carries_the_requested_witness() {
        let mut stock = SqliteStock::in_memory().unwrap();
        let contract_id = seed_consign_contract(&mut stock);
        let vout = 1u32;
        let seal = GraphSeal::new_random_vout(vout);
        let bundle = seal_bundle(contract_id, &[seal], 0);
        let bundle_id = bundle.bundle_id();
        for nonce in [1u8, 2] {
            seed_witness_bundle(&mut stock, contract_id, nonce, bundle.clone());
        }

        for nonce in [1u8, 2] {
            let witness_id = txid(nonce);
            let (consignment, _) = stock
                .transfer(
                    contract_id,
                    [OutputSeal::with(witness_id, vout)],
                    [],
                    [],
                    Some(witness_id),
                    None,
                )
                .expect("consignment should be built");
            let carried = consignment
                .bundles
                .iter()
                .find(|wb| wb.bundle.bundle_id() == bundle_id)
                .expect("the bundle is a terminal");
            assert_eq!(carried.witness_id(), witness_id, "witness {nonce} was asked for");
            let terminals = consignment
                .terminals
                .get(&bundle_id)
                .expect("bundle must be a terminal")
                .into_iter()
                .collect::<BTreeSet<_>>();
            assert_eq!(terminals, bset![BuilderSeal::Revealed(seal)]);
        }

        // nothing lands on an archived witness, so nothing can be consigned for it
        stock.upsert_witness(txid(2), WitnessOrd::Archived).unwrap();
        assert!(stock
            .transfer(contract_id, [OutputSeal::with(txid(2), vout)], [], [], Some(txid(2)), None)
            .is_err());
    }
}
