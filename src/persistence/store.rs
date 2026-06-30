// RGB ops library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 RGB-Tools developers
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

//! Unified, backend-agnostic data-access trait for RGB persistence.
//!
//! [`RgbStore`] is a *dumb* storage interface: it stores and retrieves rows and
//! blobs and knows nothing about RGB semantics. All RGB logic lives in
//! [`Stock`](super::Stock), which drives the store.
//!
//! A backend may persist the data however it likes (SQLite, PostgreSQL, a flat
//! file, ...), as long as it is picked at compile time: `schemata` and `geneses`
//! return `impl Iterator`, so the trait is not object-safe and
//! [`Stock`](super::Stock) is generic over the backend rather than holding a
//! `dyn RgbStore`.
//!
//! The trait deliberately exposes no transaction *ownership*: the
//! `begin`/`commit`/`rollback` hooks let a backend embedded in a host database
//! implement them as no-ops and leave transaction control to the host, which
//! commits the whole unit of work atomically.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::num::NonZeroU32;

use aluvm::library::{Lib, LibId};
use rgb::bitcoin::{OutPoint as Outpoint, Transaction as Tx, Txid};
use rgb::vm::WitnessOrd;
use rgb::{
    AssignmentType, BundleId, ContractId, Genesis, GlobalStateType, GraphSeal, OpId, Opout,
    OutputSeal, RevealedData, Schema, SchemaId, SecretSeal, TransitionBundle, TransitionType, Vout,
};
use strict_types::{TypeLib, TypeLibId};

use crate::containers::{SealWitness, SpvProof};

/// Kind of owned state an allocation row carries, mirroring the three RGB
/// assignment families. Backends use it to partition the assignments storage.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum AllocKind {
    /// Fungible assignment (`RevealedValue`).
    Fungible,
    /// Structured / data assignment (`RevealedData`).
    Structured,
    /// Declarative / rights assignment (`VoidState`).
    Declarative,
}

/// An allocation's seal as it is defined, not as it resolves.
///
/// A seal defined on the witness transaction has no txid of its own: it lands
/// on `vout` of whichever transaction anchors its bundle, and a bundle may be
/// anchored by several (an RBF replacement, or every commitment transaction of
/// a Lightning channel carrying the same bundle). Storing it resolved would pick
/// one of them and lose the others, so it is stored as defined and resolved
/// against a witness at read time.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct AllocSeal {
    /// The txid the seal names, or `None` for a seal on the witness transaction.
    pub txid: Option<Txid>,
    /// The output the seal closes.
    pub vout: Vout,
}

impl AllocSeal {
    /// A seal naming its own outpoint.
    pub fn explicit(seal: OutputSeal) -> Self {
        Self {
            txid: Some(seal.txid),
            vout: seal.vout,
        }
    }

    /// A seal on output `vout` of the witness transaction.
    pub fn witness_vout(vout: impl Into<Vout>) -> Self {
        Self {
            txid: None,
            vout: vout.into(),
        }
    }

    /// The outpoint the seal closes when `witness_id` anchors its bundle, or
    /// `None` for a seal on the witness transaction when no witness is given.
    pub fn resolve(self, witness_id: Option<Txid>) -> Option<OutputSeal> {
        Some(OutputSeal::with(self.txid.or(witness_id)?, self.vout))
    }
}

/// A single owned-state allocation as stored, with its value left as an opaque
/// strict-encoded blob for [`Stock`](super::Stock) to decode according to the
/// requested [`AllocKind`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AllocationRow {
    /// State family the value blob is encoded as.
    pub kind: AllocKind,
    /// The operation output this allocation belongs to (`op`, `type`, `no`).
    pub opout: Opout,
    /// The seal the state is assigned to.
    ///
    /// Reads narrowed to outpoints return it resolved, to the queried outpoint;
    /// other reads return it as defined, see [`AllocSeal`].
    pub seal: AllocSeal,
    /// Bundle the producing transition belongs to, or `None` for genesis.
    ///
    /// The witness is not here: a bundle may be anchored by more than one, and
    /// which of them is valid changes as the chain does. The caller resolves it
    /// through [`RgbStore::witnesses_of_bundles`].
    pub bundle_id: Option<BundleId>,
    /// Strict-encoded owned state (empty blob for declarative rights).
    pub value: Vec<u8>,
}

/// Selects a contract's allocations for reading.
///
/// Each narrowing is optional: start from [`Self::all`] and chain the builder
/// methods.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct AllocationFilter<'a> {
    /// Only this state family; every family when `None`.
    pub kind: Option<AllocKind>,
    /// Only this assignment type; every type when `None`.
    pub type_id: Option<AssignmentType>,
    /// Only seals landing on one of these outpoints; every seal when `None`.
    ///
    /// An empty set is not the same as `None`: it selects nothing, since no
    /// seal is a member of it.
    pub outpoints: Option<&'a BTreeSet<Outpoint>>,
    /// Which rows count as visible.
    pub visibility: Visibility,
}

impl<'a> AllocationFilter<'a> {
    /// Every allocation of the contract, narrowed by visibility alone.
    pub fn all(visibility: Visibility) -> Self {
        Self {
            kind: None,
            type_id: None,
            outpoints: None,
            visibility,
        }
    }

    /// Narrows to one state family.
    pub fn kind(mut self, kind: AllocKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Narrows to one assignment type.
    pub fn type_id(mut self, type_id: AssignmentType) -> Self {
        self.type_id = Some(type_id);
        self
    }

    /// Narrows to the seals landing on any of `outpoints`.
    pub fn at(mut self, outpoints: &'a BTreeSet<Outpoint>) -> Self {
        self.outpoints = Some(outpoints);
        self
    }
}

/// Borrowed view of an allocation row to be persisted. The caller
/// ([`Stock`](super::Stock)) has already encoded the state value; the seal is
/// stored as defined, see [`AllocSeal`].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct AllocationWrite<'a> {
    /// Owning contract.
    pub contract_id: ContractId,
    /// State family.
    pub kind: AllocKind,
    /// Operation output (`op`, `type`, `no`).
    pub opout: Opout,
    /// Seal as defined.
    pub seal: AllocSeal,
    /// Bundle id, or `None` for genesis. The witness is not stored: see
    /// [`AllocationRow::bundle_id`].
    pub bundle_id: Option<BundleId>,
    /// Strict-encoded owned state.
    pub value: &'a [u8],
}

/// Borrowed view of a global-state entry to be persisted.
///
/// Mirrors [`AllocationWrite`], and for the same reason takes the bundle rather
/// than the witness: [`GlobalOut`](crate::contract::GlobalOut) names a witness
/// transaction, which is not what a stored row can be tied to.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct GlobalStateWrite<'a> {
    /// Owning contract.
    pub contract_id: ContractId,
    /// Global state type.
    pub type_id: GlobalStateType,
    /// Operation the entry belongs to.
    pub opid: OpId,
    /// Index of the entry within its operation's state of this type.
    pub index: u16,
    /// Nonce, as the operation declared it.
    pub nonce: u64,
    /// Bundle of the producing transition, `None` for genesis.
    pub bundle_id: Option<BundleId>,
    /// Type of the producing transition, `None` for genesis.
    pub transition_type: Option<TransitionType>,
    /// The entry's value.
    pub value: &'a RevealedData,
}

/// One global-state entry as [`RgbStore::globals`] returns it.
///
/// Deliberately not a [`GlobalOut`](crate::contract::GlobalOut): that carries
/// an [`OpWitness`](crate::contract::OpWitness), which names a witness
/// transaction, and no stored column can name the right one - a bundle may
/// have several and which is valid changes with the chain. The caller resolves
/// the bundle to a witness through [`RgbStore::witnesses_of_bundles`] and
/// assembles the [`GlobalOut`](crate::contract::GlobalOut) then.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct GlobalStateRow {
    /// Operation the entry belongs to.
    pub opid: OpId,
    /// Index of the entry within its operation's state of this type.
    pub index: u16,
    /// Nonce, as the operation declared it.
    pub nonce: u64,
    /// Bundle of the producing transition, `None` for genesis.
    pub bundle_id: Option<BundleId>,
    /// Type of the producing transition, `None` for genesis (set together with
    /// `bundle_id`).
    pub transition_type: Option<TransitionType>,
    /// The entry's value.
    pub value: RevealedData,
}

/// Which rows a state query is to return.
///
/// The only piece of RGB semantics the store is asked to understand, and it is
/// here because it is the one filter that decides how much work a query is: a
/// backend which can answer it in an indexed join answers it for the rows it
/// returns, where a caller filtering afterwards has to read every
/// [`WitnessOrd`] and every invalidated operation the store holds, whatever
/// the size of the answer. Kept as an enum rather than a predicate so the
/// vocabulary stays the trait's and no backend has to reimplement RGB's
/// notion of validity.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Visibility {
    /// Every stored row, whatever the state of its witness or operation.
    All,
    /// Only rows which currently count towards contract state: the row's
    /// witness, if it has one, must be known and
    /// [`WitnessOrd::is_valid`](rgb::vm::WitnessOrd::is_valid), and the
    /// operation which produced it must not be marked invalid.
    ///
    /// A row whose witness has no stored [`WitnessOrd`] is excluded, exactly
    /// as an archived one is: state hanging off a witness the store cannot
    /// place on the chain is not state anyone can spend.
    Valid,
}

/// What a store transaction is opened for.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TxMode {
    /// The transaction only reads. Several may run at once, and a backend
    /// should take no more than the access it needs.
    Read,
    /// The transaction writes. A backend should take the exclusive access it
    /// needs upfront rather than upgrading half-way through, so that
    /// contention is reported before any of the work is done.
    Write,
}

/// What [`RgbStore::begin`] found.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TxBegin {
    /// The call opened the transaction, and its caller owns it.
    Opened,
    /// A transaction was already open, so the call opened nothing. Its caller
    /// owns no transaction and must neither commit nor roll back.
    AlreadyOpen,
}

/// Backend-agnostic data access for all RGB persistent data. Contains **no**
/// RGB logic; see the module docs.
pub trait RgbStore: std::fmt::Debug {
    /// Data-retrieval / storage error. Treated as connectivity-class by
    /// [`Stock`](super::Stock).
    type Error: Clone + Eq + Error;

    // ----- transaction control ------------------------------------------------

    /// Opens a storage transaction, reporting whether it opened one or found
    /// one already open. A backend folded into a host transaction may leave the
    /// opening to the host and always answer [`TxBegin::AlreadyOpen`].
    ///
    /// **Deciding and opening must be one indivisible step.** A backend reached
    /// from more than one thread cannot let two callers each find no
    /// transaction and both believe they opened one: the loser would write
    /// inside the winner's transaction and commit it half-way through.
    ///
    /// Takes `&self`: reads are transactional too, and they are issued through
    /// shared references. A backend which needs to mutate to open one keeps
    /// that behind its own interior mutability, as the SQLite one does.
    ///
    /// Within an open transaction, writes must be visible to subsequent reads on
    /// the same store: [`Stock`](super::Stock) reads back data it wrote earlier
    /// in the same unit of work.
    fn begin(&self, mode: TxMode) -> Result<TxBegin, Self::Error>;
    /// Commits the storage transaction. On error the caller issues a
    /// [`rollback`](Self::rollback), so an implementation must not leave a
    /// partially-applied transaction open after a failed commit.
    fn commit(&self) -> Result<(), Self::Error>;
    /// Rolls back the storage transaction. Infallible and idempotent: it may be
    /// called with no transaction open (e.g. after a failed commit) and must
    /// swallow any error, since the caller has no way to act on it.
    fn rollback(&self);

    // ----- schema definitions --------------------------------------------------

    /// Fetches a schema by id.
    fn schema(&self, schema_id: SchemaId) -> Result<Option<Schema>, Self::Error>;
    /// Inserts a schema if absent. Stock has verified its definition first.
    fn put_schema(&mut self, schema: &Schema) -> Result<(), Self::Error>;
    /// Lazily iterates all stored schemata.
    fn schemata(&self) -> impl Iterator<Item = Result<Schema, Self::Error>> + '_;

    // ----- type libraries / AluVM libraries -----------------------------------

    /// The strict type libraries a stored schema was defined by, keyed by id.
    ///
    /// Schema definitions are decomposed on the way in: their type libraries and
    /// their AluVM libraries are stored individually, alongside those of every
    /// other imported schema, so a definition is never kept whole.
    /// [`crate::persistence::Stock`] puts one back together on read, and derives
    /// the type system from the libraries returned here rather than storing it.
    ///
    /// Empty for a schema which is not stored, which no caller can tell from a
    /// stored schema defined by no library: [`crate::persistence::Stock`] has
    /// the schema in hand before it asks.
    fn type_libs(&self, schema_id: SchemaId) -> Result<BTreeMap<TypeLibId, TypeLib>, Self::Error>;
    /// Inserts a type library if absent, and links it to `schema_id`.
    ///
    /// Both halves are idempotent: a library shared between schemata is stored
    /// once and linked to each.
    fn put_type_lib(&mut self, schema_id: SchemaId, type_lib: &TypeLib) -> Result<(), Self::Error>;
    /// Fetches an AluVM library by id.
    fn aluvm_lib(&self, aluvm_lib_id: LibId) -> Result<Option<Lib>, Self::Error>;
    /// Inserts an AluVM library if absent.
    fn put_aluvm_lib(&mut self, aluvm_lib: &Lib) -> Result<(), Self::Error>;

    // ----- contracts (genesis) ------------------------------------------------

    /// Fetches a contract's genesis.
    fn genesis(&self, contract_id: ContractId) -> Result<Option<Genesis>, Self::Error>;
    /// Upserts a contract's genesis (already merge-revealed by Stock).
    fn put_genesis(&mut self, genesis: &Genesis) -> Result<(), Self::Error>;
    /// Lazily iterates all stored geneses.
    fn geneses(&self) -> impl Iterator<Item = Result<Genesis, Self::Error>> + '_;
    /// Convenience join: the schema backing a contract's genesis.
    fn contract_schema(&self, contract_id: ContractId) -> Result<Option<Schema>, Self::Error>;

    // ----- bundles / witnesses / secret seals ---------------------------------

    /// Fetches a transition bundle by id.
    fn bundle(&self, bundle_id: BundleId) -> Result<Option<TransitionBundle>, Self::Error>;
    /// Upserts a bundle (already merge-revealed by Stock).
    fn put_bundle(&mut self, bundle: &TransitionBundle) -> Result<(), Self::Error>;

    /// Fetches a seal witness by its witness txid.
    fn witness(&self, txid: Txid) -> Result<Option<SealWitness>, Self::Error>;
    /// Upserts a seal witness (already merge-revealed by Stock).
    fn put_witness(&mut self, witness: &SealWitness) -> Result<(), Self::Error>;

    /// Just the transaction of a witness. Serves witness re-resolution, which
    /// needs the TX and the SPV proof but never the commitment proofs, and runs
    /// over every witness in the store.
    fn witness_tx(&self, txid: Txid) -> Result<Option<Tx>, Self::Error>;
    /// Just the SPV proof of a witness, `None` when the witness is unknown or
    /// carries no proof - the two are not distinguished, since neither yields a
    /// proof to check.
    fn witness_spv_proof(&self, txid: Txid) -> Result<Option<SpvProof>, Self::Error>;
    /// Replaces the SPV proof of a witness, leaving the rest of it untouched.
    /// A witness the store does not know is left alone; the return reports
    /// whether a row was updated.
    ///
    /// A `spv_proof` of `None` clears the stored one, which is what a proof the
    /// chain has refuted gets. Reports whether the row changed.
    ///
    /// Proofs are refuted by reorgs and refreshed by retrievals far more often
    /// than the witness they belong to changes, so this must not be a
    /// read-modify-write of the whole record.
    fn set_witness_spv_proof(
        &mut self,
        txid: Txid,
        spv_proof: Option<&SpvProof>,
    ) -> Result<bool, Self::Error>;

    /// Resolves a concealed seal to its revealed graph seal, if known.
    fn seal_of_secret(&self, secret_seal: SecretSeal) -> Result<Option<GraphSeal>, Self::Error>;
    /// Stores a secret seal keyed by its concealment.
    fn put_secret_seal(
        &mut self,
        graph_seal: &GraphSeal,
        secret_seal: SecretSeal,
    ) -> Result<(), Self::Error>;

    // ----- global state -------------------------------------------------------

    /// Global-state entries for a contract/type, narrowed by `visibility`.
    ///
    /// No [`WitnessOrd`] rides along: an entry is tied to its bundle, and which
    /// witness of that bundle is the one to report - and with which ord - is
    /// decided by `Ord` on `WitnessPos`, which weighs layers against each other
    /// and so cannot be a column order. The caller resolves it through
    /// [`Self::witnesses_of_bundles`], in one batch for all the bundles it saw.
    ///
    /// Ordering and per-type limits likewise stay with Stock: the consensus
    /// ordering is whatever the `Ord` impls on `GlobalOrd`/`OpOrd`/`WitnessPos`
    /// in rgb-consensus say, so only the validity filter is the store's to
    /// apply - a backend must never sort these rows itself.
    fn globals(
        &self,
        contract_id: ContractId,
        type_id: GlobalStateType,
        visibility: Visibility,
    ) -> Result<Vec<GlobalStateRow>, Self::Error>;
    /// Inserts a global-state entry if absent.
    fn put_global(&mut self, global_state: GlobalStateWrite<'_>) -> Result<(), Self::Error>;

    // ----- allocations (owned state) ------------------------------------------

    /// A contract's allocations, narrowed by `filter`.
    fn allocations(
        &self,
        contract_id: ContractId,
        filter: AllocationFilter<'_>,
    ) -> Result<Vec<AllocationRow>, Self::Error>;
    /// The allocations on `outpoints` across every contract at once, each row
    /// tagged with the contract assigning it.
    ///
    /// Separate from [`Self::allocations`] because it is not contract-scoped:
    /// it answers "which contracts assign state to these outpoints, and which
    /// state" with one query instead of a [`Self::contracts_assigning`] lookup
    /// followed by a per-contract query over the same rows.
    fn all_allocations_at_outpoints(
        &self,
        outpoints: &BTreeSet<Outpoint>,
        visibility: Visibility,
    ) -> Result<Vec<(ContractId, AllocationRow)>, Self::Error>;
    /// Inserts an allocation row if absent.
    fn put_allocation(&mut self, allocation: AllocationWrite<'_>) -> Result<(), Self::Error>;

    // ----- WitnessOrd / invalid ops -------------------------------------------

    /// The [`WitnessOrd`] of a single witness.
    fn witness_ord(&self, txid: Txid) -> Result<Option<WitnessOrd>, Self::Error>;
    /// The [`WitnessOrd`] of each named witness, the ones the store does not
    /// know being absent from the result rather than an error.
    ///
    /// The batch form of [`Self::witness_ord`], for callers weighing a known
    /// set of witnesses. Prefer it to [`Self::all_witness_ords`] wherever the
    /// set is known: the store holds a witness for every transfer ever seen,
    /// and that table grows without bound while the set asked about usually
    /// does not.
    fn witness_ords(
        &self,
        txids: &BTreeSet<Txid>,
    ) -> Result<BTreeMap<Txid, WitnessOrd>, Self::Error>;
    /// The witnesses worth re-resolving against the chain: those not
    /// [`WitnessOrd::Ignored`](rgb::vm::WitnessOrd::Ignored), and, if mined, at
    /// or above `min_height`.
    ///
    /// A witness deep enough in the chain, or deliberately ignored, is not
    /// asked about again, so this is the candidate set rather than the whole
    /// table - and it is only a set: the caller takes the ids to a resolver,
    /// and what is stored is decided later from the answers, not from the
    /// [`WitnessOrd`]s as they stood here. Callers wanting a specific witness
    /// regardless take it from [`Self::witness_ords`].
    fn witness_ords_to_refresh(
        &self,
        min_height: NonZeroU32,
    ) -> Result<BTreeSet<Txid>, Self::Error>;
    /// Every stored [`WitnessOrd`].
    ///
    /// Grows with everything the store has ever seen; reach for
    /// [`Self::witness_ords`] or [`Self::witness_ords_to_refresh`] unless the
    /// whole table really is the answer.
    fn all_witness_ords(&self) -> Result<BTreeMap<Txid, WitnessOrd>, Self::Error>;
    /// Upserts a [`WitnessOrd`].
    fn put_witness_ord(&mut self, txid: Txid, ord: WitnessOrd) -> Result<(), Self::Error>;

    /// All operations marked invalid.
    ///
    /// A whole-table read, and deliberately so: the table holds only what
    /// reorgs have invalidated and nothing has revalidated since, so it is
    /// bounded by outstanding reorg damage - not, like the witness tables, by
    /// everything the stock has ever seen. The revalidation walk uses it as a
    /// working set, testing and removing arbitrary members as it goes.
    fn all_invalid_ops(&self) -> Result<BTreeSet<OpId>, Self::Error>;
    /// Whether any of `opids` is currently marked invalid.
    fn any_op_invalid(&self, opids: &BTreeSet<OpId>) -> Result<bool, Self::Error>;
    /// Records whether an operation is currently valid, adding it to or
    /// removing it from the set [`Self::all_invalid_ops`] returns.
    fn set_op_validity(&mut self, opid: OpId, valid: bool) -> Result<(), Self::Error>;

    // ----- index: contract / bundle / op graph --------------------------------

    /// Whether the store holds this contract at all.
    ///
    /// A contract is known by its genesis and nothing else.
    fn contract_registered(&self, contract_id: ContractId) -> Result<bool, Self::Error>;

    /// Contract a bundle belongs to.
    fn bundle_contract(&self, bundle_id: BundleId) -> Result<Option<ContractId>, Self::Error>;
    /// Records the bundle->contract mapping (Stock checks for conflicts first).
    fn put_bundle_contract(
        &mut self,
        bundle_id: BundleId,
        contract_id: ContractId,
    ) -> Result<(), Self::Error>;

    /// Witnesses anchoring a bundle.
    fn bundle_witnesses(&self, bundle_id: BundleId) -> Result<BTreeSet<Txid>, Self::Error>;
    /// The same, for many bundles at once: state rows name a bundle, and a
    /// reader turning a page of them into witnesses would otherwise ask once
    /// per row. Bundles with no witness on file are absent from the map.
    fn witnesses_of_bundles(
        &self,
        bundle_ids: &BTreeSet<BundleId>,
    ) -> Result<BTreeMap<BundleId, BTreeSet<Txid>>, Self::Error>;
    /// Bundles a witness anchors: the reverse of [`Self::bundle_witnesses`].
    ///
    /// A reorg moving a witness across the validity boundary asks this for
    /// every witness it moved. The witness record's merkle block holds the
    /// same answer, but reading it there decodes the whole witness; this is
    /// the index answer, and it is also the more precise one - it lists the
    /// bundles this stock indexed, which are the only ones whose operations it
    /// can revalidate or invalidate.
    fn bundles_of_witness(&self, txid: Txid) -> Result<BTreeSet<BundleId>, Self::Error>;
    /// Adds a witness to a bundle's witness set.
    fn put_bundle_witness(&mut self, bundle_id: BundleId, txid: Txid) -> Result<(), Self::Error>;

    /// Bundle an operation belongs to.
    fn bundle_of_op(&self, opid: OpId) -> Result<Option<BundleId>, Self::Error>;
    /// Operations of a bundle: the reverse of [`Self::bundle_of_op`], and the
    /// index answer to what would otherwise mean decoding a whole bundle to
    /// call `known_transitions_opids` on it.
    fn ops_in_bundle(&self, bundle_id: BundleId) -> Result<BTreeSet<OpId>, Self::Error>;
    /// Records the op->bundle mapping (Stock checks for conflicts first).
    fn put_op_bundle(&mut self, opid: OpId, bundle_id: BundleId) -> Result<(), Self::Error>;

    /// Bundles that spend an operation's outputs.
    fn child_bundles_of_op(&self, opid: OpId) -> Result<BTreeSet<BundleId>, Self::Error>;
    /// The transitions spending an operation's outputs, each with the bundle it
    /// belongs to: the spend edges [`Self::put_op_input`] recorded, read
    /// forward. Powers the invalidation walk without decoding any bundle.
    fn child_ops_of_op(&self, opid: OpId) -> Result<BTreeSet<(OpId, BundleId)>, Self::Error>;
    /// Opouts spent by an operation, its transition inputs, each identified by
    /// producing op + assignment type + output index. Empty for genesis / roots.
    /// Powers the sender's index-only backward closure walk (no transition loaded).
    fn input_opouts_for_op(&self, opid: OpId) -> Result<BTreeSet<Opout>, Self::Error>;
    /// Records a spend edge: `spent_opout` (the consumed opout) is spent by
    /// `child_opid` inside `child_bundle_id`.
    fn put_op_input(
        &mut self,
        spent_opout: Opout,
        child_opid: OpId,
        child_bundle_id: BundleId,
    ) -> Result<(), Self::Error>;

    // ----- index: outpoint->opout and secret-seal->opout ------------------------

    /// Opouts a contract assigns to each of the given outpoints, grouped by
    /// outpoint (an outpoint may carry several opouts). Outpoints with no
    /// allocation are absent from the map, so Stock detects unknown ones by
    /// diffing the request against the keys.
    fn opouts_at(
        &self,
        contract_id: ContractId,
        outpoints: &BTreeSet<Outpoint>,
    ) -> Result<BTreeMap<Outpoint, BTreeSet<Opout>>, Self::Error>;
    /// Contracts that assign state to any of the given outpoints.
    fn contracts_assigning(
        &self,
        outpoints: &BTreeSet<Outpoint>,
    ) -> Result<BTreeSet<ContractId>, Self::Error>;
    /// Records an outpoint->opout entry (Stock resolved the outpoint).
    fn put_outpoint_opout(
        &mut self,
        contract_id: ContractId,
        outpoint: Outpoint,
        opout: Opout,
    ) -> Result<(), Self::Error>;

    /// Opouts a contract assigns to any of the given confidential seals. Seals
    /// the contract assigns nothing to simply contribute nothing: unlike
    /// [`Self::opouts_at`], the caller does not diff the result against the
    /// request.
    fn opouts_by_secrets(
        &self,
        contract_id: ContractId,
        secret_seals: &BTreeSet<SecretSeal>,
    ) -> Result<BTreeSet<Opout>, Self::Error>;
    /// Records a confidential-seal->opout entry (the seal is not resolvable to
    /// an outpoint, so it is indexed by its secret).
    fn put_secret_opout(
        &mut self,
        contract_id: ContractId,
        secret_seal: SecretSeal,
        opout: Opout,
    ) -> Result<(), Self::Error>;
}
