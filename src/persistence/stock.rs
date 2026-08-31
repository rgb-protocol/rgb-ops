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

use std::collections::{btree_map, hash_map, BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;
use std::num::NonZeroU32;

use amplify::confinement::{Confined, LargeOrdSet};
use rgb::bitcoin::block::Header;
use rgb::bitcoin::{OutPoint as Outpoint, Transaction as Tx, Txid};
use rgb::dbc::{Anchor, Proof};
use rgb::validation::{
    OpoutsDagData, OpoutsDagInfo, ResolveWitness, SchemaDefinition, SchemaRules, SpvProof,
    UnsafeHistoryMap, WitnessOrdProvider, WitnessResolverError, WitnessStatus,
};
use rgb::vm::{WitnessOrd, WitnessPos};
use rgb::{
    AssignmentType, BundleId, ChainNet, ContractId, ExposedSeal, Genesis, GraphSeal, Identity,
    KnownTransition, Layer1, OpId, Operation, Opout, OutputSeal, Schema, SchemaId, SecretSeal,
    Transition, TransitionType, UnrelatedTransition,
};
use strict_types::FieldName;

use super::{
    ContractStateRead, Index, IndexError, IndexInconsistency, IndexProvider, IndexReadProvider,
    IndexWriteProvider, MemContract, Stash, StashDataError, StashError, StashInconsistency,
    StashProvider, StashReadProvider, StashWriteProvider, State, StateError, StateInconsistency,
    StateProvider, StateReadProvider, StateWriteProvider, StoreTransaction,
};
use crate::containers::{
    BuilderSeal, Consignment, ConsignmentExt, ConsignmentVer, Contract, Fascia, SealWitness,
    TerminalSeals, Transfer, ValidConsignment, ValidContract, ValidTransfer, WitnessBundle,
};
use crate::contract::{
    AllocatedState, BuilderError, ContractBuilder, ContractData, IssuerWrapper, LinkError,
    LinkableIssuerWrapper, LinkableSchemaWrapper, SchemaWrapper, TransitionBuilder,
};
use crate::indexers::ResolveSpvProof;
use crate::info::{ContractInfo, SchemaInfo};
use crate::MergeRevealError;

pub type ContractAssignments = HashMap<OutputSeal, HashMap<Opout, AllocatedState>>;

type SortedBundlesWithDag = (Vec<WitnessBundle>, Option<OpoutsDagData>);

type ConsignmentWithOptDag<const TRANSFER: bool> = (Consignment<TRANSFER>, Option<OpoutsDagData>);

/// Consignment and its operations DAG
pub type ConsignmentWithDag<const TRANSFER: bool> = (Consignment<TRANSFER>, OpoutsDagData);

/// What a consignment must include and how it is composed, threaded through the
/// composition helpers of [`Stock`].
struct ConsignParams<'a> {
    /// Seals whose state must be included and reported as terminals.
    outputs: &'a [OutputSeal],
    /// Blinded seals whose state must be included and reported as terminals.
    secret_seals: &'a [SecretSeal],
    /// If set, restrict the consignment to bundles closed by this witness.
    ///
    /// Unused when composing from a [`Fascia`], which carries its own witness.
    witness_id: Option<Txid>,
    /// See [`Stock::transfer`].
    spv_resolver: Option<&'a dyn ResolveSpvProof>,
    /// Whether to also build the operations DAG.
    build_opouts_dag: bool,
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

/// Outcome of updating the ord of a witness.
enum WitnessOrdChange {
    /// The ord did not change, or changed without crossing validity.
    Kept,
    /// The witness became valid; carries the bundles it is known to witness.
    BecameValid(BTreeSet<BundleId>),
    /// The witness became invalid; carries the bundles it is known to witness.
    BecameInvalid(BTreeSet<BundleId>),
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum StockError<S: StashProvider, H: StateProvider, P: IndexProvider, E: Error = Infallible> {
    InvalidInput(E),
    Resolver(String),
    StashRead(<S as StashReadProvider>::Error),
    StashWrite(<S as StashWriteProvider>::Error),
    IndexRead(<P as IndexReadProvider>::Error),
    IndexWrite(<P as IndexWriteProvider>::Error),
    StateRead(<H as StateReadProvider>::Error),
    StateWrite(<H as StateWriteProvider>::Error),

    #[display(doc_comments)]
    /// schema {0} is not known to this stash.
    ///
    /// Consignments carry only their schema id, so the schema must be
    /// imported out-of-band (via a schema definition) before a contract
    /// using it can be issued or accepted.
    SchemaNotImported(SchemaId),

    #[from]
    #[display(doc_comments)]
    /// {0}
    ///
    /// It may happen due to RGB ops library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    StashInconsistency(StashInconsistency),

    #[from]
    #[display(doc_comments)]
    /// state for contract {0} is not known.
    ///
    /// It may happen due to RGB ops library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    StateInconsistency(StateInconsistency),

    #[from]
    #[display(doc_comments)]
    /// {0}
    ///
    /// It may happen due to RGB ops library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    IndexInconsistency(IndexInconsistency),

    #[from]
    StashData(StashDataError),

    /// valid (non-archived) witness is absent in the list of witnesses for a
    /// state transition bundle.
    AbsentValidWitness,

    /// Unable to sort bundles because of data inconsistency.
    BundlesInconsistency,

    /// witness {0} can't be resolved: {1}
    WitnessUnresolved(Txid, WitnessResolverError),

    #[from]
    /// contract link is not valid: {1}
    ContractLinkError(LinkError),
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider, E: Error> From<StashError<S>>
    for StockError<S, H, P, E>
{
    fn from(err: StashError<S>) -> Self {
        match err {
            StashError::ReadProvider(err) => Self::StashRead(err),
            StashError::WriteProvider(err) => Self::StashWrite(err),
            StashError::Data(e) => Self::StashData(e),
            StashError::Inconsistency(e) => Self::StashInconsistency(e),
        }
    }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider, E: Error> From<StateError<H>>
    for StockError<S, H, P, E>
{
    fn from(err: StateError<H>) -> Self {
        match err {
            StateError::ReadProvider(err) => Self::StateRead(err),
            StateError::WriteProvider(err) => Self::StateWrite(err),
            StateError::Inconsistency(e) => Self::StateInconsistency(e),
            StateError::Resolver(id, e) => Self::WitnessUnresolved(id, e),
            StateError::AbsentValidWitness => Self::AbsentValidWitness,
        }
    }
}
impl<S: StashProvider, H: StateProvider, P: IndexProvider, E: Error> From<IndexError<P>>
    for StockError<S, H, P, E>
{
    fn from(err: IndexError<P>) -> Self {
        match err {
            IndexError::ReadProvider(err) => Self::IndexRead(err),
            IndexError::WriteProvider(err) => Self::IndexWrite(err),
            IndexError::Inconsistency(e) => Self::IndexInconsistency(e),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ConsignError {
    /// unable to construct consignment: too many terminals provided.
    TooManyTerminals,

    /// unable to construct consignment: invalid number of secret seals.
    InvalidSecretSealsNumber,

    /// unable to construct consignment: history size too large, resulting in
    /// too many transitions.
    TooManyBundles,

    #[from]
    #[display(inner)]
    MergeReveal(MergeRevealError),

    #[from]
    #[display(inner)]
    Transition(UnrelatedTransition),

    /// the spent state from transition {1} inside bundle {0} is concealed.
    Concealed(BundleId, OpId),

    /// the requested contract is unrelated to other inputs.
    UnrelatedContract(ContractId),

    /// the transition {1} inside bundle {0} is concealed.
    ConcealedTransition(BundleId, OpId),

    /// the transition {1} inside bundle {0} appears after its child.
    UnorderedTransition(BundleId, OpId),
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<ConsignError>
    for StockError<S, H, P, ConsignError>
{
    fn from(err: ConsignError) -> Self { Self::InvalidInput(err) }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<MergeRevealError>
    for StockError<S, H, P, ConsignError>
{
    fn from(err: MergeRevealError) -> Self { Self::InvalidInput(err.into()) }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<UnrelatedTransition>
    for StockError<S, H, P, ConsignError>
{
    fn from(err: UnrelatedTransition) -> Self { Self::InvalidInput(err.into()) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ComposeError {
    /// no outputs available to store state of type {0}
    NoExtraOrChange(AssignmentType),

    /// the provided PSBT doesn't pay any sats to the RGB beneficiary address.
    NoBeneficiaryOutput,

    /// beneficiary output number is given when secret seal is used.
    BeneficiaryVout,

    /// expired invoice.
    InvoiceExpired,

    /// the invoice contains no contract information.
    NoContract,

    /// the invoice requirements can't be fulfilled using available assets or
    /// smart contract state.
    InsufficientState,

    /// the spent UTXOs contain too many seals which can't fit the state
    /// transition input limit.
    TooManyInputs,

    /// the operation produces too many extra state transitions which can't fit
    /// the container requirements.
    TooManyExtras,

    #[from]
    #[display(inner)]
    Builder(BuilderError),
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<ComposeError>
    for StockError<S, H, P, ComposeError>
{
    fn from(err: ComposeError) -> Self { Self::InvalidInput(err) }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<BuilderError>
    for StockError<S, H, P, ComposeError>
{
    fn from(err: BuilderError) -> Self { Self::InvalidInput(err.into()) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum FasciaError {
    /// bundle {1} for contract {0} contains invalid transition input map.
    InvalidBundle(ContractId, BundleId),
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<FasciaError>
    for StockError<S, H, P, FasciaError>
{
    fn from(err: FasciaError) -> Self { Self::InvalidInput(err) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum InputError {
    #[from]
    Compose(ComposeError),
    #[from]
    Consign(ConsignError),
    #[from]
    Fascia(FasciaError),
}

macro_rules! stock_err_conv {
    (Infallible, $err2:ty) => {
        impl<S: StashProvider, H: StateProvider, P: IndexProvider>
            From<StockError<S, H, P, Infallible>> for StockError<S, H, P, $err2>
        {
            fn from(err: StockError<S, H, P, Infallible>) -> Self {
                stock_err_conv!(@body err, e, match e {})
            }
        }
    };
    ($err1:ty, $err2:ty) => {
        impl<S: StashProvider, H: StateProvider, P: IndexProvider> From<StockError<S, H, P, $err1>>
            for StockError<S, H, P, $err2>
        {
            fn from(err: StockError<S, H, P, $err1>) -> Self {
                stock_err_conv!(@body err, e, StockError::InvalidInput(e.into()))
            }
        }
    };
    (@body $err:expr, $e:ident, $($invalid:tt)*) => {
        match $err {
            StockError::InvalidInput($e) => $($invalid)*,
            StockError::Resolver(e) => StockError::Resolver(e),
            StockError::StashRead(e) => StockError::StashRead(e),
            StockError::StashWrite(e) => StockError::StashWrite(e),
            StockError::IndexRead(e) => StockError::IndexRead(e),
            StockError::IndexWrite(e) => StockError::IndexWrite(e),
            StockError::StateRead(e) => StockError::StateRead(e),
            StockError::StateWrite(e) => StockError::StateWrite(e),
            StockError::AbsentValidWitness => StockError::AbsentValidWitness,
            StockError::BundlesInconsistency => StockError::BundlesInconsistency,
            StockError::StashData(e) => StockError::StashData(e),
            StockError::StashInconsistency(e) => StockError::StashInconsistency(e),
            StockError::StateInconsistency(e) => StockError::StateInconsistency(e),
            StockError::IndexInconsistency(e) => StockError::IndexInconsistency(e),
            StockError::WitnessUnresolved(id, e) => StockError::WitnessUnresolved(id, e),
            StockError::ContractLinkError(e) => StockError::ContractLinkError(e),
            StockError::SchemaNotImported(e) => StockError::SchemaNotImported(e),
        }
    };
}

stock_err_conv!(Infallible, ComposeError);
stock_err_conv!(Infallible, ConsignError);
stock_err_conv!(Infallible, FasciaError);
stock_err_conv!(Infallible, InputError);
stock_err_conv!(ComposeError, InputError);
stock_err_conv!(ConsignError, InputError);
stock_err_conv!(FasciaError, InputError);

pub type StockErrorAll<S, H, P> = StockError<S, H, P, InputError>;

/// Resolver serving a set of already-resolved witness statuses, falling back
/// to the wrapped resolver for the other witnesses.
struct PreresolvedWitnesses<R: ResolveWitness> {
    statuses: BTreeMap<Txid, WitnessStatus>,
    fallback: R,
}

impl<R: ResolveWitness> ResolveWitness for PreresolvedWitnesses<R> {
    fn resolve_witness(&self, witness_id: Txid) -> Result<WitnessStatus, WitnessResolverError> {
        match self.statuses.get(&witness_id) {
            Some(status) => Ok(status.clone()),
            None => self.fallback.resolve_witness(witness_id),
        }
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        self.fallback.check_chain_net(chain_net)
    }
}

#[derive(Debug)]
pub struct Stock<S: StashProvider, H: StateProvider, P: IndexProvider> {
    stash: Stash<S>,
    state: State<H>,
    index: Index<P>,
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> Default for Stock<S, H, P>
where
    S: Default,
    H: Default,
    P: Default,
{
    fn default() -> Self {
        Self {
            stash: default!(),
            state: default!(),
            index: default!(),
        }
    }
}

impl<S: StashProvider, H: StateProvider, P: IndexProvider> Stock<S, H, P> {
    pub fn with(stash_provider: S, state_provider: H, index_provider: P) -> Self {
        Stock {
            stash: Stash::new(stash_provider),
            state: State::new(state_provider),
            index: Index::new(index_provider),
        }
    }

    #[doc(hidden)]
    pub fn as_stash_provider(&self) -> &S { self.stash.as_provider() }
    #[doc(hidden)]
    pub fn as_state_provider(&self) -> &H { self.state.as_provider() }
    #[doc(hidden)]
    pub fn as_index_provider(&self) -> &P { self.index.as_provider() }

    #[doc(hidden)]
    pub fn as_stash_provider_mut(&mut self) -> &mut S { self.stash.as_provider_mut() }
    #[doc(hidden)]
    pub fn as_state_provider_mut(&mut self) -> &mut H { self.state.as_provider_mut() }
    #[doc(hidden)]
    pub fn as_index_provider_mut(&mut self) -> &mut P { self.index.as_provider_mut() }

    pub fn schemata(&self) -> impl Iterator<Item = Result<SchemaInfo, StockError<S, H, P>>> + '_ {
        self.stash
            .schemata()
            .map(|r| r.map(|s| SchemaInfo::with(&s)).map_err(StockError::from))
    }

    pub fn schema(&self, schema_id: SchemaId) -> Result<Schema, StockError<S, H, P>> {
        Ok(self.stash.schema(schema_id)?)
    }

    /// Loads a schema which is required to be already imported, reporting its
    /// absence as [`StockError::SchemaNotImported`] rather than as a stash
    /// inconsistency: a missing schema means the user has not imported the
    /// schema definition, not that the storage is corrupted.
    fn load_imported_schema(&self, schema_id: SchemaId) -> Result<Schema, StockError<S, H, P>> {
        match self.stash.schema(schema_id) {
            Ok(schema) => Ok(schema),
            Err(StashError::Inconsistency(StashInconsistency::SchemaAbsent(id))) => {
                Err(StockError::SchemaNotImported(id))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn contracts(
        &self,
    ) -> impl Iterator<Item = Result<ContractInfo, StockError<S, H, P>>> + '_ {
        self.stash
            .geneses()
            .map(|r| r.map(|g| ContractInfo::with(&g)).map_err(StockError::from))
    }

    /// Iterates over ids of all contract assigning state to the provided set of
    /// output seals.
    pub fn contracts_assigning(
        &self,
        outputs: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeSet<ContractId>, StockError<S, H, P>> {
        let outputs = outputs
            .into_iter()
            .map(|o| o.into())
            .collect::<BTreeSet<_>>();
        Ok(self.index.contracts_assigning(outputs)?)
    }

    #[allow(clippy::type_complexity)]
    fn contract_raw(
        &self,
        contract_id: ContractId,
    ) -> Result<(SchemaId, H::ContractRead<'_>, ContractInfo), StockError<S, H, P>> {
        let state = self.state.contract_state(contract_id)?;
        let schema_id = state.schema_id();
        Ok((schema_id, state, self.contract_info(contract_id)?))
    }

    pub fn contract_info(
        &self,
        contract_id: ContractId,
    ) -> Result<ContractInfo, StockError<S, H, P>> {
        Ok(ContractInfo::with(&self.stash.genesis(contract_id)?))
    }

    pub fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<H::ContractRead<'_>, StockError<S, H, P>> {
        self.state
            .contract_state(contract_id)
            .map_err(StockError::from)
    }

    pub fn contract_wrapper<C: IssuerWrapper>(
        &self,
        contract_id: ContractId,
    ) -> Result<C::Wrapper<H::ContractRead<'_>>, StockError<S, H, P>> {
        self.schema_wrapper::<C::Wrapper<_>>(contract_id)
    }

    fn schema_wrapper<'a, C: SchemaWrapper<H::ContractRead<'a>>>(
        &'a self,
        contract_id: ContractId,
    ) -> Result<C, StockError<S, H, P>> {
        let contract_data = self.contract_data(contract_id)?;
        Ok(C::with(contract_data))
    }

    /// Returns the contract data for the given contract ID
    pub fn contract_data(
        &self,
        contract_id: ContractId,
    ) -> Result<ContractData<H::ContractRead<'_>>, StockError<S, H, P>> {
        let (schema_id, state, info) = self.contract_raw(contract_id)?;
        let rules = self.schema_rules(schema_id)?;

        Ok(ContractData { state, rules, info })
    }

    /// Returns the contract data of a validated consignment, reading the rules
    /// it was issued under from the stash.
    ///
    /// The schema must have been imported (see
    /// [`Stock::import_schema_definition`]): a consignment carries neither the
    /// schema nor the type system, only the schema id its genesis commits to.
    pub fn consignment_data<const TRANSFER: bool>(
        &self,
        consignment: &ValidConsignment<TRANSFER>,
    ) -> Result<ContractData<MemContract>, StockError<S, H, P>> {
        let rules = self.schema_rules(consignment.genesis.schema_id)?;
        Ok(consignment.build_contract_data(&rules))
    }

    pub fn contract_assignments_for(
        &self,
        contract_id: ContractId,
        outpoints: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<ContractAssignments, StockError<S, H, P>> {
        let outputs: BTreeSet<Outpoint> = outpoints.into_iter().map(|o| o.into()).collect();

        let state = self.contract_state(contract_id)?;

        let mut res =
            HashMap::<OutputSeal, HashMap<Opout, AllocatedState>>::with_capacity(outputs.len());

        for item in state.fungible_all() {
            let item = item.expect("state read failure");
            let outpoint = item.seal.into();
            if outputs.contains::<Outpoint>(&outpoint) {
                res.entry(item.seal)
                    .or_default()
                    .insert(item.opout, AllocatedState::Amount(item.state));
            }
        }

        for item in state.data_all() {
            let item = item.expect("state read failure");
            let outpoint = item.seal.into();
            if outputs.contains::<Outpoint>(&outpoint) {
                res.entry(item.seal)
                    .or_default()
                    .insert(item.opout, AllocatedState::Data(item.state));
            }
        }

        for item in state.rights_all() {
            let item = item.expect("state read failure");
            let outpoint = item.seal.into();
            if outputs.contains::<Outpoint>(&outpoint) {
                res.entry(item.seal)
                    .or_default()
                    .insert(item.opout, AllocatedState::Void);
            }
        }

        Ok(res)
    }

    pub fn contract_builder(
        &self,
        issuer: impl Into<Identity>,
        schema_id: SchemaId,
        chain_net: ChainNet,
    ) -> Result<ContractBuilder, StockError<S, H, P>> {
        Ok(self
            .stash
            .contract_builder(issuer.into(), schema_id, chain_net)?)
    }

    pub fn transition_builder(
        &self,
        contract_id: ContractId,
        transition_name: impl Into<FieldName>,
    ) -> Result<TransitionBuilder, StockError<S, H, P>> {
        Ok(self
            .stash
            .transition_builder(contract_id, transition_name)?)
    }

    pub fn transition_builder_raw(
        &self,
        contract_id: ContractId,
        transition_type: TransitionType,
    ) -> Result<TransitionBuilder, StockError<S, H, P>> {
        Ok(self
            .stash
            .transition_builder_raw(contract_id, transition_type)?)
    }

    /// The verified [`SchemaRules`] for `schema_id`.
    ///
    /// The stash keeps the schema, the type system and the AluVM libraries
    /// apart, so the rules are reassembled - and re-checked - on each call.
    pub fn schema_rules(&self, schema_id: SchemaId) -> Result<SchemaRules, StockError<S, H, P>> {
        Ok(self.stash.schema_rules(schema_id)?)
    }

    pub fn export_contract(
        &self,
        contract_id: ContractId,
    ) -> Result<Contract, StockError<S, H, P, ConsignError>> {
        self.consign::<false>(contract_id, [], &ConsignParams {
            outputs: &[],
            secret_seals: &[],
            witness_id: None,
            spv_resolver: None,
            build_opouts_dag: false,
        })
        .map(|(c, _)| c)
    }

    /// Compose a transfer consignment.
    ///
    /// `spv_resolver` controls the SPV proofs the consignment carries, letting the
    /// receiver verify the witnesses from block headers alone. With `None` only the proofs
    /// already in the stash are used; with `Some` the missing ones are retrieved on the
    /// spot, so that a wallet need not keep a proof stored for every witness it knows.
    ///
    /// Retrieval is best-effort: a witness whose proof cannot be obtained simply travels
    /// without one, which is always legal. In particular the witness of the transfer being
    /// composed has no proof, since the consignment is handed over before it is broadcast.
    pub fn transfer(
        &self,
        contract_id: ContractId,
        outputs: impl AsRef<[OutputSeal]>,
        secret_seals: impl AsRef<[SecretSeal]>,
        opids: impl IntoIterator<Item = OpId>,
        witness_id: Option<Txid>,
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<Transfer, StockError<S, H, P, ConsignError>> {
        self.consign(contract_id, opids, &ConsignParams {
            outputs: outputs.as_ref(),
            secret_seals: secret_seals.as_ref(),
            witness_id,
            spv_resolver,
            build_opouts_dag: false,
        })
        .map(|(c, _)| c)
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
    ) -> Result<ConsignmentWithDag<true>, StockError<S, H, P, ConsignError>> {
        self.consign(contract_id, opids, &ConsignParams {
            outputs: outputs.as_ref(),
            secret_seals: secret_seals.as_ref(),
            witness_id,
            spv_resolver,
            build_opouts_dag: true,
        })
        .map(|(c, d)| (c, d.unwrap()))
    }

    fn sort_bundles(
        &self,
        bundles: BTreeMap<BundleId, (WitnessBundle, u32)>,
        contract_id: ContractId,
        build_opouts_dag: bool,
        genesis: &Genesis,
    ) -> Result<SortedBundlesWithDag, StockError<S, H, P, ConsignError>> {
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
                        let input_bundle_id = self.index.bundle_id_for_op(input.op)?;
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
                        let input_bundle_id = self.index.bundle_id_for_op(input.op)?;
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
    ) -> Result<ConsignmentWithOptDag<TRANSFER>, StockError<S, H, P, ConsignError>> {
        // Collect initial set of opids to include
        let mut opids = opids.into_iter().collect::<HashSet<_>>();
        opids.extend(
            self.index
                .public_opouts(contract_id)?
                .into_iter()
                .chain(
                    self.index
                        .opouts_by_outputs(contract_id, params.outputs.iter().copied())?,
                )
                .chain(
                    self.index
                        .opouts_by_terminals(params.secret_seals.iter().copied())?,
                )
                .map(|opout| opout.op),
        );

        self.consign_operations(contract_id, opids, params)
    }

    fn consign_operations<const TRANSFER: bool>(
        &self,
        contract_id: ContractId,
        opids: impl IntoIterator<Item = OpId>,
        params: &ConsignParams,
    ) -> Result<ConsignmentWithOptDag<TRANSFER>, StockError<S, H, P, ConsignError>> {
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

            let bundle_id = self.index.bundle_id_for_op(transition.id())?;

            let (witness_ids, bundle_contract_id) = self.index.bundle_info(bundle_id)?;
            let witness_ids = witness_ids.into_iter().collect::<Vec<_>>();
            // skip bundles not associated to the terminals witness
            if witness_id.is_some_and(|wid| !witness_ids.contains(&wid)) {
                continue;
            }
            let bundle_witness = match bundle_witnesses.get(&bundle_id) {
                Some(&witness) => witness,
                None => {
                    let witness = self.state.select_valid_witness(&witness_ids)?;
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
                        params.spv_resolver,
                    )?,
                );
            };
        }
        self.consign_bundles(contract_id, bundles, parent_opids, terminal_seals, params)
    }

    fn consign_bundles<const TRANSFER: bool>(
        &self,
        contract_id: ContractId,
        mut bundles: BTreeMap<BundleId, (WitnessBundle, u32)>,
        mut parent_opids: Vec<OpId>,
        terminal_seals: BTreeMap<BundleId, BTreeSet<BuilderSeal<GraphSeal>>>,
        params: &ConsignParams,
    ) -> Result<ConsignmentWithOptDag<TRANSFER>, StockError<S, H, P, ConsignError>> {
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
            let bundle_id = self.index.bundle_id_for_op(transition.id())?;
            if let Some((wbundle, _)) = bundles.get_mut(&bundle_id) {
                wbundle.bundle.reveal_transition(transition)?;
            } else {
                let (witness_ids, bundle_contract_id) = self.index.bundle_info(bundle_id)?;
                let bundle_witness = self.state.select_valid_witness(witness_ids)?;
                bundles.insert(
                    bundle_id,
                    self.witness_bundle(
                        bundle_id,
                        id,
                        bundle_contract_id,
                        bundle_witness,
                        params.spv_resolver,
                    )?,
                );
            };
        }

        let genesis = self.stash.genesis(contract_id)?.clone();

        // fail early: a consignment can only be produced for a schema this
        // stash knows, since the consignment itself carries just its id
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
                        .map_err(|_| ConsignError::InvalidSecretSealsNumber)
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?,
        )
        .map_err(|_| ConsignError::TooManyTerminals)?;

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
    ) -> Result<Consignment<true>, StockError<S, H, P, ConsignError>> {
        self.consign_from_fascia(contract_id, opids, fascia, &ConsignParams {
            outputs: outputs.as_ref(),
            secret_seals: secret_seals.as_ref(),
            witness_id: None,
            spv_resolver,
            build_opouts_dag: false,
        })
        .map(|(c, _)| c)
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
    ) -> Result<ConsignmentWithDag<true>, StockError<S, H, P, ConsignError>> {
        self.consign_from_fascia(contract_id, opids, fascia, &ConsignParams {
            outputs: outputs.as_ref(),
            secret_seals: secret_seals.as_ref(),
            witness_id: None,
            spv_resolver,
            build_opouts_dag: true,
        })
        .map(|(c, d)| (c, d.expect("build_opouts_dag=true")))
    }

    fn consign_from_fascia(
        &self,
        contract_id: ContractId,
        opids: impl IntoIterator<Item = OpId>,
        fascia: &Fascia,
        params: &ConsignParams,
    ) -> Result<ConsignmentWithOptDag<true>, StockError<S, H, P, ConsignError>> {
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
        contract_bundle.known_transitions = Confined::from_checked(rev_bundle_transitions);
        let SealWitness {
            tx: witness_tx,
            merkle_block,
            dbc_proof,
            spv_proof: _,
        } = fascia.seal_witness().clone();
        let anchor = Anchor::new(
            merkle_block
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
        )
    }

    fn store_transaction<E: Error>(
        &mut self,
        f: impl FnOnce(
            &mut Stash<S>,
            &mut State<H>,
            &mut Index<P>,
        ) -> Result<(), StockError<S, H, P, E>>,
    ) -> Result<(), StockError<S, H, P, E>> {
        // FIXME: this doesn't guarantee atomicity
        self.state.begin_transaction()?;
        self.stash
            .begin_transaction()
            .inspect_err(|_| self.stash.rollback_transaction())?;
        self.index.begin_transaction().inspect_err(|_| {
            self.state.rollback_transaction();
            self.stash.rollback_transaction();
        })?;
        f(&mut self.stash, &mut self.state, &mut self.index)?;
        self.index
            .commit_transaction()
            .map_err(StockError::from)
            .and_then(|_| self.state.commit_transaction().map_err(StockError::from))
            .and_then(|_| self.stash.commit_transaction().map_err(StockError::from))
            .inspect_err(|_| {
                self.state.rollback_transaction();
                self.stash.rollback_transaction();
                self.index.rollback_transaction();
            })
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
    /// The stash does not keep the definition itself: it stores the schema, the
    /// type system derived from the definition's type libraries, and the AluVM
    /// libraries, alongside those of every other imported schema.
    pub fn import_schema_definition(
        &mut self,
        schema_def: SchemaDefinition,
    ) -> Result<(), StockError<S, H, P>> {
        self.stash.begin_transaction()?;
        self.stash.consume_schema_definition(schema_def)?;
        self.stash.commit_transaction()?;
        Ok(())
    }

    pub fn import_contract<R: ResolveWitness>(
        &mut self,
        contract: ValidContract,
        resolver: R,
    ) -> Result<(), StockError<S, H, P>> {
        self.consume_consignment(contract, resolver)
    }

    pub fn accept_transfer<R: ResolveWitness>(
        &mut self,
        contract: ValidTransfer,
        resolver: R,
    ) -> Result<(), StockError<S, H, P>> {
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
        if proof.validate(tx.compute_txid(), &header).is_err() {
            return Ok(SpvCheck::Refuted);
        }
        let pos = WitnessPos::with(layer1, proof.block_height, header.time as i64)
            .ok_or(WitnessResolverError::InvalidResolverData)?;
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
    ) -> Result<(), StockError<S, H, P>> {
        let consignment = self.stash.resolve_secrets(consignment.into_consignment())?;
        let consignment_bundles: Vec<(Txid, BundleId, BTreeSet<OpId>)> = consignment
            .bundled_witnesses()
            .map(|wb| {
                let bundle = wb.bundle();
                (wb.witness_id(), bundle.bundle_id(), bundle.known_transitions_opids())
            })
            .collect();

        // resolve the consignment witnesses with accept-time resolutions,
        // which may differ from the ones seen at validation time if a reorg
        // happened in the meantime. Witnesses carrying a still-valid SPV proof are
        // resolved from it, so that a client with no access to a TX indexer can
        // consume the consignment it has just validated.
        let layer1 = consignment.genesis().chain_net.layer1();
        let mut headers = HashMap::new();
        let mut statuses: BTreeMap<Txid, WitnessStatus> = bmap![];
        let mut unvetted_proofs: BTreeMap<Txid, SpvProof> = bmap![];
        for witness_bundle in consignment.bundled_witnesses() {
            let witness_id = witness_bundle.witness_id();
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
            // do not store a proof that failed to verify, or that nothing here could
            // verify. Keep one the stash already holds when the check is `Uncheckable`:
            // that means headers cannot be fetched, not that the proof is bad. A
            // refuted proof is dropped even if already stored.
            if matches!(check, SpvCheck::Refuted | SpvCheck::Uncheckable) {
                if let Some(proof) = &witness_bundle.spv_proof {
                    let stashed = self
                        .stash
                        .witness(witness_id)
                        .is_ok_and(|w| w.spv_proof.as_ref() == Some(proof));
                    if matches!(check, SpvCheck::Refuted) || !stashed {
                        unvetted_proofs.insert(witness_id, proof.clone());
                    }
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

        // witness ords as they will be once the consignment is consumed:
        // the stored ones overlaid with the fresh resolutions
        let mut witnesses = self
            .as_state_provider()
            .all_witness_ords()
            .map_err(StockError::StateRead)?;
        let known_witness_ids: BTreeSet<Txid> = witnesses.keys().copied().collect();
        for (witness_id, status) in &statuses {
            witnesses.insert(*witness_id, status.witness_ord());
        }

        // collect the bundles left without any valid witness, re-resolving
        // the alternative witnesses known for a bundle before giving up on it
        let mut bundles_without_witness: Vec<BundleId> = vec![];
        for (witness_id, bundle_id, _) in &consignment_bundles {
            if witnesses.get(witness_id).is_some_and(|ord| ord.is_valid()) {
                continue;
            }
            let alt_witness_ids: BTreeSet<Txid> = match self.index.bundle_info(*bundle_id) {
                Ok((witness_ids, _)) => witness_ids,
                // the bundle is not known yet, so it has no other witnesses
                Err(IndexError::Inconsistency(IndexInconsistency::BundleWitnessUnknown(_))) => {
                    bset![]
                }
                Err(e) => return Err(e.into()),
            };
            let mut has_valid_witness = false;
            for alt_witness_id in alt_witness_ids {
                if let btree_map::Entry::Vacant(e) = statuses.entry(alt_witness_id) {
                    let status = resolver
                        .resolve_witness(alt_witness_id)
                        .map_err(|e| StockError::WitnessUnresolved(alt_witness_id, e))?;
                    witnesses.insert(alt_witness_id, status.witness_ord());
                    e.insert(status);
                }
                if witnesses
                    .get(&alt_witness_id)
                    .is_some_and(|ord| ord.is_valid())
                {
                    has_valid_witness = true;
                    break;
                }
            }
            if !has_valid_witness {
                bundles_without_witness.push(*bundle_id);
            }
        }

        // the consignment is stale: store the chain knowledge acquired while
        // checking it, then refuse it
        if !bundles_without_witness.is_empty() {
            let mut ops_to_invalidate = vec![];
            for bundle_id in &bundles_without_witness {
                if let Ok(bundle) = self.stash.bundle(*bundle_id) {
                    ops_to_invalidate.extend(bundle.known_transitions_opids());
                }
            }
            self.state.begin_transaction()?;
            // store the fresh ords of the already-known witnesses
            for (witness_id, status) in &statuses {
                if known_witness_ids.contains(witness_id) {
                    self.state
                        .upsert_witness(*witness_id, status.witness_ord())?;
                }
            }
            // set the known operations of the bundles left without a valid
            // witness as invalid, together with all their descendants
            let mut visited = bset!();
            for opid in ops_to_invalidate {
                self.set_ops_as_invalid(opid, &mut visited)?;
            }
            self.state.commit_transaction()?;
            return Err(StockError::AbsentValidWitness);
        }

        // serve the accept-time resolutions to the consignment consumption,
        // so the stored ords cannot diverge from the ones checked above
        let resolver = PreresolvedWitnesses {
            statuses,
            fallback: resolver,
        };
        // The consignment carries only its schema id: the schema itself must
        // already be in the stash, imported out-of-band via a schema definition.
        let schema = self.load_imported_schema(consignment.schema_id())?.clone();
        self.store_transaction(move |stash, state, index| {
            state.update_from_consignment(&consignment, &schema, &resolver)?;
            index.index_consignment(&consignment)?;
            stash.consume_consignment(consignment)?;
            Ok(())
        })?;

        // A proof the consignment carried for a witness the stash had none for was stored
        // along with it, so the ones left unvetted above are dropped now. Only when the
        // stash actually holds the unvetted proof: where it had a proof of its own that one
        // was kept, and it is not the one which went unvetted. Between this and
        // `Stash::consume_witness`, the stash is left holding only proofs which either
        // verified here or verified when they arrived and have not been refuted since.
        for (witness_id, unvetted) in unvetted_proofs {
            if self
                .stash
                .witness(witness_id)
                .is_ok_and(|w| w.spv_proof.as_ref() == Some(&unvetted))
            {
                self.stash.set_spv_proof(witness_id, None)?;
            }
        }

        // the consignment was validated and all its bundles have a valid
        // witness: revalidate any of its operations that a reorg had
        // previously set as invalid, together with their descendants
        let mut invalid_ops = self
            .as_state_provider()
            .invalid_ops()
            .map_err(StockError::StateRead)?;
        if consignment_bundles
            .iter()
            .any(|(_, _, opids)| opids.iter().any(|opid| invalid_ops.contains(opid)))
        {
            self.state.begin_transaction()?;
            let witnesses = self
                .as_state_provider()
                .all_witness_ords()
                .map_err(StockError::StateRead)?;
            let mut maybe_became_valid_opids: BTreeSet<OpId> = consignment_bundles
                .iter()
                .flat_map(|(_, _, opids)| opids.iter().copied())
                .collect();
            for (_, bundle_id, opids) in &consignment_bundles {
                for opid in opids {
                    self.maybe_update_ops_as_valid(
                        *opid,
                        *bundle_id,
                        &mut invalid_ops,
                        &mut maybe_became_valid_opids,
                        &witnesses,
                    )?;
                }
            }
            self.state.commit_transaction()?;
        }

        Ok(())
    }

    /// Imports fascia into the stash, index and inventory.
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
    ) -> Result<(), StockError<S, H, P, FasciaError>> {
        self.store_transaction(move |stash, state, index| {
            let witness_id = fascia.witness_id();
            stash.consume_witness(fascia.seal_witness())?;

            for (contract_id, bundle) in fascia.into_bundles() {
                bundle
                    .check_opid_commitments()
                    .map_err(|_| FasciaError::InvalidBundle(contract_id, bundle.bundle_id()))?;

                index.index_bundle(contract_id, &bundle, witness_id)?;
                state.update_from_bundle(
                    contract_id,
                    &bundle,
                    witness_id,
                    &witness_ord_provider,
                )?;
                stash.consume_bundle(bundle)?;
            }
            Ok(())
        })
    }

    fn transition(&self, opid: OpId) -> Result<Transition, StockError<S, H, P, ConsignError>> {
        let bundle_id = self.index.bundle_id_for_op(opid)?;
        let bundle = self.stash.bundle(bundle_id)?;
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
    /// If the witness is mined, an SPV proof is attached: the one from the stash, or
    /// failing that one retrieved from `spv_resolver`. This is best-effort: a witness
    /// whose proof cannot be retrieved is left without one.
    ///
    /// A proof coming from the stash wins over the resolver and is shipped as is, without
    /// being checked against the chain. Reconciling the stash with a reorg is the job of
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
        spv_resolver: Option<&dyn ResolveSpvProof>,
    ) -> Result<(WitnessBundle, u32), StockError<S, H, P, ConsignError>> {
        let bundle = self
            .stash
            .bundle(bundle_id)?
            .to_concealed_except(opid)
            .map_err(|e| StockError::from(ConsignError::Transition(e)))?;
        let witness = self.stash.witness(witness_id)?;
        let tx = witness.tx.clone();
        let Ok(mpc_proof) = witness.merkle_block.to_merkle_proof(contract_id.into()) else {
            return Err(StashInconsistency::WitnessMissesContract(
                witness_id,
                bundle_id,
                contract_id,
                witness.dbc_proof.method(),
            )
            .into());
        };
        let anchor = Anchor::new(mpc_proof, witness.dbc_proof.clone());

        let spv_proof = witness.spv_proof.clone().or_else(|| {
            // a non-mined witness has no proof to retrieve. This is what leaves the
            // witness of the transfer being composed without one, as it is not
            // broadcast yet.
            let resolver = spv_resolver.filter(|_| matches!(witness_ord, WitnessOrd::Mined(_)))?;
            resolver.resolve_spv_proof(witness_id).ok()
        });

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

    pub fn store_secret_seal(&mut self, seal: GraphSeal) -> Result<bool, StockError<S, H, P>> {
        Ok(self.stash.store_secret_seal(seal)?)
    }

    fn op_children(&self, opid: OpId) -> Result<Vec<(OpId, BundleId)>, StockError<S, H, P>> {
        // collect all bundle ids of the children of the operation
        let children_bundle_ids = match self.index.bundle_ids_children_of_op(opid) {
            Ok(bundle_ids) => bundle_ids,
            Err(IndexError::Inconsistency(IndexInconsistency::BundleAbsent(_))) => {
                // this transition has no children yet
                small_bset![]
            }
            Err(e) => return Err(e.into()),
        };
        // collect all opids of transitions consuming outputs of the operation,
        // together with their bundle ids
        let mut children = vec![];
        for child_bundle_id in children_bundle_ids {
            let child_bundle = self.stash.bundle(child_bundle_id)?;
            for kt in &child_bundle.known_transitions {
                if kt.transition.inputs.iter().any(|input| input.op == opid) {
                    children.push((kt.opid, child_bundle_id));
                }
            }
        }
        Ok(children)
    }

    fn set_ops_as_invalid(
        &mut self,
        opid: OpId,
        visited: &mut BTreeSet<OpId>,
    ) -> Result<(), StockError<S, H, P>> {
        // descendant trees of different operations can overlap and converge;
        // visit each operation only once per update
        // the visited set is local to the update on purpose: operations
        // already invalid from previous updates must still be re-visited,
        // since new descendants may have been added in the meantime
        if !visited.insert(opid) {
            return Ok(());
        }
        // add operation to set of invalid operations
        self.state.update_op(opid, false)?;
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
        invalid_ops: &mut LargeOrdSet<OpId>,
        maybe_became_valid_opids: &mut BTreeSet<OpId>,
        witnesses: &BTreeMap<Txid, WitnessOrd>,
    ) -> Result<bool, StockError<S, H, P>> {
        let bundle = self.stash.bundle(bundle_id)?;
        let transition = bundle
            .get_transition(opid)
            .ok_or(StashInconsistency::OperationAbsent(opid))?
            .clone();

        // a valid operation needs a valid witness for its bundle
        let bundle_witness_ids = self.index.bundle_info(bundle_id)?.0;
        let mut valid = bundle_witness_ids
            .into_iter()
            .any(|id| witnesses.get(&id).is_some_and(|ord| ord.is_valid()));

        // recursively visit operation ancestors
        if valid {
            for input in &transition.inputs {
                let input_opid = input.op;
                // process parent first if its status is also uncertain
                if maybe_became_valid_opids.contains(&input_opid) {
                    let input_bundle_id = self.index.bundle_id_for_op(input_opid)?;
                    if !self.maybe_update_ops_as_valid(
                        input_opid,
                        input_bundle_id,
                        invalid_ops,
                        maybe_became_valid_opids,
                        witnesses,
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
            self.state.update_op(opid, true)?;
            invalid_ops.remove(&opid).unwrap();
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
                    witnesses,
                )?;
            }
        }

        Ok(valid)
    }

    fn update_witness_ord(
        &mut self,
        resolver: impl ResolveWitness,
        id: &Txid,
        ord: &mut WitnessOrd,
        layer1: Layer1,
        headers: &mut HashMap<NonZeroU32, Header>,
    ) -> Result<WitnessOrdChange, StockError<S, H, P>> {
        // a witness with a stored SPV proof is refreshed from it, so that a client
        // with no access to a TX indexer can still detect a reorg affecting it
        let spv_check = match self.stash.witness(*id) {
            Ok(witness) => Self::resolve_witness_spv(
                &resolver,
                &witness.tx,
                witness.spv_proof.as_ref(),
                layer1,
                headers,
            )
            .map_err(|e| StockError::WitnessUnresolved(*id, e))?,
            Err(_) => SpvCheck::Absent,
        };
        if matches!(spv_check, SpvCheck::Refuted) {
            self.stash.set_spv_proof(*id, None)?;
        }
        let new = match spv_check {
            SpvCheck::Confirmed(status) => status,
            SpvCheck::Absent | SpvCheck::Uncheckable | SpvCheck::Refuted => resolver
                .resolve_witness(*id)
                .map_err(|e| StockError::WitnessUnresolved(*id, e))?,
        }
        .witness_ord();
        let changed = *ord != new;
        let mut change = WitnessOrdChange::Kept;
        if changed {
            let bundle_valid = match (*ord, new) {
                (WitnessOrd::Archived, _) => Some(true),
                (_, WitnessOrd::Archived) => Some(false),
                _ => None,
            };
            // report witnesses that became valid or invalid
            if let Some(valid) = bundle_valid {
                let seal_witness = self.stash.witness(*id)?;
                let bundle_ids: BTreeSet<_> = seal_witness.known_bundle_ids().collect();
                change = if valid {
                    WitnessOrdChange::BecameValid(bundle_ids)
                } else {
                    WitnessOrdChange::BecameInvalid(bundle_ids)
                };
            }
            // save the changed witness ord
            self.state.upsert_witness(*id, new)?;
            *ord = new
        }
        Ok(change)
    }

    pub fn update_witnesses(
        &mut self,
        resolver: impl ResolveWitness,
        after_height: u32,
        force_witnesses: Vec<Txid>,
    ) -> Result<UpdateRes, StockError<S, H, P>> {
        let after_height = NonZeroU32::new(after_height).unwrap_or(NonZeroU32::MIN);
        // needed to turn an SPV proof's height into a `WitnessPos`; all the contracts of a
        // stock live on the same chain, so any genesis answers for all of them
        let layer1 = self
            .stash
            .geneses()
            .next()
            .transpose()?
            .map(|genesis| genesis.chain_net.layer1())
            .unwrap_or(Layer1::Bitcoin);
        let mut succeeded = 0;
        let mut failed = map![];
        self.state.begin_transaction()?;
        let mut witnesses = self
            .as_state_provider()
            .all_witness_ords()
            .map_err(StockError::StateRead)?;
        let mut became_invalid_witnesses = bmap!();
        let mut became_valid_witnesses = bmap!();
        let mut headers = HashMap::new();
        // 1. update witness ord of all witnesses
        for (id, ord) in &mut witnesses {
            if matches!(ord, WitnessOrd::Ignored) && !force_witnesses.contains(id) {
                continue;
            }
            if matches!(ord, WitnessOrd::Mined(pos) if pos.height() < after_height) {
                continue;
            }
            match self.update_witness_ord(&resolver, id, ord, layer1, &mut headers) {
                Ok(change) => {
                    match change {
                        WitnessOrdChange::BecameValid(bundle_ids) => {
                            became_valid_witnesses.insert(*id, bundle_ids);
                        }
                        WitnessOrdChange::BecameInvalid(bundle_ids) => {
                            became_invalid_witnesses.insert(*id, bundle_ids);
                        }
                        WitnessOrdChange::Kept => {}
                    }
                    succeeded += 1;
                }
                Err(err) => {
                    failed.insert(*id, err.to_string());
                }
            }
        }

        // 2. set invalidity of operations
        let mut visited = bset!();
        for bundle_ids in became_invalid_witnesses.values() {
            for bundle_id in bundle_ids {
                let bundle_witness_ids = self.index.bundle_info(*bundle_id)?.0;
                // set the bundle operations as invalid only if there are no valid witnesses
                // associated to the bundle
                if bundle_witness_ids
                    .iter()
                    .all(|id| !witnesses.get(id).unwrap().is_valid())
                {
                    // set all the bundle operations and their descendants as invalid
                    for opid in self.stash.bundle(*bundle_id)?.known_transitions_opids() {
                        self.set_ops_as_invalid(opid, &mut visited)?;
                    }
                }
            }
        }

        // 3. set validity of operations
        let mut maybe_became_valid_opids = bset!();
        // get all operations that became invalid and ones that were already invalid
        let mut invalid_ops_pre = self
            .as_state_provider()
            .invalid_ops()
            .map_err(StockError::StateRead)?;
        for bundle_ids in became_valid_witnesses.values() {
            for bundle_id in bundle_ids {
                // store operations that may become valid (to be sure their ancestors are
                // checked)
                maybe_became_valid_opids
                    .extend(self.stash.bundle(*bundle_id)?.known_transitions_opids());
            }
        }
        for bundle_ids in became_valid_witnesses.values() {
            for bundle_id in bundle_ids {
                // check if the bundle operations and their descendants are now valid
                for opid in self.stash.bundle(*bundle_id)?.known_transitions_opids() {
                    self.maybe_update_ops_as_valid(
                        opid,
                        *bundle_id,
                        &mut invalid_ops_pre,
                        &mut maybe_became_valid_opids,
                        &witnesses,
                    )?;
                }
            }
        }

        self.state.commit_transaction()?;
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
    ) -> Result<bool, StockError<S, H, P>> {
        Ok(self.stash.set_spv_proof(witness_id, Some(proof))?)
    }

    pub fn upsert_witness(
        &mut self,
        witness_id: Txid,
        witness_ord: WitnessOrd,
    ) -> Result<(), StockError<S, H, P>> {
        self.store_transaction(move |_stash, state, _index| {
            Ok(state.upsert_witness(witness_id, witness_ord)?)
        })
    }

    fn _check_bundle_history(
        &self,
        bundle_id: &BundleId,
        safe_height: NonZeroU32,
        contract_history: &mut HashMap<ContractId, HashMap<u32, HashSet<Txid>>>,
    ) -> Result<(), StockError<S, H, P>> {
        let (bundle_witness_ids, contract_id) = self.index.bundle_info(*bundle_id)?;
        let (witness_id, ord) = self.state.select_valid_witness(bundle_witness_ids)?;
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

        // recursively check bundle ancestors
        let bundle = self.stash.bundle(*bundle_id)?.clone();
        for KnownTransition { transition, .. } in bundle.known_transitions {
            for input in &transition.inputs {
                let input_opid = input.op;
                let input_bundle_id = match self.index.bundle_id_for_op(input_opid) {
                    Ok(id) => Some(id),
                    Err(IndexError::Inconsistency(IndexInconsistency::BundleAbsent(_))) => {
                        // reached genesis
                        None
                    }
                    Err(e) => return Err(e.into()),
                };

                if let Some(input_bundle_id) = input_bundle_id {
                    self._check_bundle_history(&input_bundle_id, safe_height, contract_history)?;
                }
            }
        }

        Ok(())
    }

    pub fn get_outpoint_unsafe_history(
        &self,
        outpoint: Outpoint,
        safe_height: NonZeroU32,
    ) -> Result<HashMap<ContractId, UnsafeHistoryMap>, StockError<S, H, P>> {
        let mut contract_history: HashMap<ContractId, HashMap<u32, HashSet<Txid>>> = HashMap::new();

        for id in self.contracts_assigning([outpoint])? {
            let state = self.contract_assignments_for(id, [outpoint])?;
            for opid in state
                .values()
                .flat_map(|assigns| assigns.keys().map(|opout| opout.op))
            {
                let bundle_id = self.index.bundle_id_for_op(opid)?;
                self._check_bundle_history(&bundle_id, safe_height, &mut contract_history)?;
            }
        }

        Ok(contract_history)
    }

    pub fn validate_contracts_link<Parent: LinkableIssuerWrapper, Child: LinkableIssuerWrapper>(
        &self,
        parent_contract_id: ContractId,
        child_contract_id: ContractId,
    ) -> Result<(), StockError<S, H, P>> {
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
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct UpdateRes {
    pub succeeded: usize,
    pub failed: HashMap<Txid, String>,
}

#[cfg(all(test, feature = "sqlite"))]
mod test {
    use std::sync::mpsc;
    use std::time::Duration;

    use amplify::confinement::{NonEmptyOrdMap, NonEmptyOrdSet, NonEmptyVec};
    use amplify::ByteArray;
    use baid64::FromBaid64Str;
    use rgb::assignments::AssignVec;
    use rgb::bitcoin::hashes::Hash;
    use rgb::bitcoin::{absolute, transaction};
    use rgb::commit_verify::mpc::{self, MerkleBlock, MerkleTree, MultiSource};
    use rgb::commit_verify::{Conceal, DigestExt, Sha256, TryCommitVerify};
    use rgb::txout::BlindSeal;
    use rgb::validation::DbcProof;
    use rgb::vm::WitnessOrd;
    use rgb::{
        AssignRights, AssignmentType, Assignments, Inputs, TransitionBundle, TypedAssigns,
        VoidState, Vout,
    };
    use strict_encoding::StrictDumb;

    use super::*;
    use crate::persistence::sql::{open_in_memory, SqliteStock};
    use crate::persistence::{IndexWriteProvider, StashWriteProvider};

    #[test]
    fn test_consign() {
        let mut stock = open_in_memory().unwrap();
        let seal = GraphSeal::new_random_vout(Vout::from_u32(0));
        let secret_seal = seal.conceal();

        stock.store_secret_seal(seal).unwrap();
        let contract_id =
            ContractId::from_baid64_str("rgb:qFuT6DN8-9AuO95M-7R8R8Mc-AZvs7zG-obum1Va-BRnweKk")
                .unwrap();
        if let Ok(transfer) = stock.consign::<true>(contract_id, [], &ConsignParams {
            outputs: &[],
            secret_seals: &[secret_seal],
            witness_id: None,
            spv_resolver: None,
            build_opouts_dag: false,
        }) {
            println!("{transfer:?}")
        }
    }

    #[test]
    fn test_export_contract() {
        let stock = open_in_memory().unwrap();
        let contract_id =
            ContractId::from_baid64_str("rgb:qFuT6DN8-9AuO95M-7R8R8Mc-AZvs7zG-obum1Va-BRnweKk")
                .unwrap();
        if let Ok(contract) = stock.export_contract(contract_id) {
            println!("{:?}", contract.contract_id())
        }
    }

    #[test]
    fn test_schema_rules() {
        let stock = open_in_memory().unwrap();
        let hasher = Sha256::default();
        let schema_id = SchemaId::from(hasher);
        if let Ok(rules) = stock.schema_rules(schema_id) {
            println!("{:?}", rules.schema_id())
        }
    }

    #[test]
    fn test_transition_builder() {
        let stock = open_in_memory().unwrap();
        let hasher = Sha256::default();

        let bytes_hash = hasher.finish();
        let contract_id = ContractId::copy_from_slice(bytes_hash).unwrap();

        if let Ok(builder) = stock.transition_builder(contract_id, "transfer") {
            println!("{:?}", builder.transition_type())
        }
    }

    /// The descendant guard in `maybe_update_ops_as_valid` makes sure that a
    /// subtree reachable through multiple revalidated parents is walked only
    /// once. With a chain of k diamonds (op splitting to two ops merging back
    /// into one) the unguarded walk visits the tail of the chain O(2^k)
    /// times: with k = 64 it never terminates, so a removed guard shows up
    /// here as a watchdog timeout.
    #[test]
    fn maybe_update_ops_as_valid_diamond_chain() {
        const DIAMONDS: usize = 64;

        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut stock = open_in_memory().unwrap();
            let contract_id =
                ContractId::from_baid64_str("rgb:qFuT6DN8-9AuO95M-7R8R8Mc-AZvs7zG-obum1Va-BRnweKk")
                    .unwrap();
            let witness_id = Txid::from_byte_array([0xCE; 32]);
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
            let mut register = |stock: &mut SqliteStock,
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
                stock.stash.consume_bundle(bundle.clone()).unwrap();
                stock
                    .index
                    .index_bundle(contract_id, &bundle, witness_id)
                    .unwrap();
                // everything starts as invalid
                stock.state.update_op(opid, false).unwrap();
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
            let mut invalid_ops = stock.as_state_provider().invalid_ops().unwrap();
            let mut maybe_became_valid_opids = all_opids;
            let witnesses = bmap! { witness_id => WitnessOrd::Tentative };
            let valid = stock
                .maybe_update_ops_as_valid(
                    root_opid,
                    root_bundle_id,
                    &mut invalid_ops,
                    &mut maybe_became_valid_opids,
                    &witnesses,
                )
                .unwrap();

            assert!(valid);
            assert!(stock.as_state_provider().invalid_ops().unwrap().is_empty());
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
    fn seed_contract(stock: &mut SqliteStock) -> ContractId {
        let schema = Schema::strict_dumb();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        let provider = stock.stash.as_provider_mut();
        provider.replace_schema(schema).unwrap();
        provider.replace_genesis(genesis).unwrap();
        stock
            .index
            .as_provider_mut()
            .register_contract(contract_id)
            .unwrap();
        contract_id
    }

    /// An MPC block committing `bundle_id` under `contract_id`
    fn mpc_block(contract_id: ContractId, bundle_id: BundleId) -> MerkleBlock {
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
            mpc_block(contract_id, bundle_id),
            DbcProof::strict_dumb(),
            None,
        )
    }

    /// Persists `bundle` as anchored to the transaction identified by `nonce`
    fn seed_witness_bundle(
        stock: &mut SqliteStock,
        contract_id: ContractId,
        nonce: u8,
        bundle: TransitionBundle,
    ) -> BundleId {
        let witness_id = txid(nonce);
        let bundle_id = bundle.bundle_id();
        stock
            .stash
            .consume_witness(&seal_witness(contract_id, bundle_id, nonce))
            .unwrap();
        stock
            .state
            .upsert_witness(witness_id, WitnessOrd::Tentative)
            .unwrap();
        stock.stash.consume_bundle(bundle.clone()).unwrap();
        stock
            .index
            .index_bundle(contract_id, &bundle, witness_id)
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
        let mut stock = open_in_memory().unwrap();
        let contract_id = seed_contract(&mut stock);

        let witness_nonce = 0xAA;
        let witness_id = txid(witness_nonce);
        let (seals, outputs, expected) = terminal_seal_cases(witness_id);
        let bundle_id = seed_witness_bundle(
            &mut stock,
            contract_id,
            witness_nonce,
            seal_bundle(contract_id, &seals, 0),
        );

        let consignment = stock
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

    /// Apply terminal_seal_cases to stock.transfer_from_fascia
    #[test]
    fn terminal_seals_from_fascia() {
        let mut stock = open_in_memory().unwrap();
        let contract_id = seed_contract(&mut stock);

        let witness_nonce = 0xAA;
        let (seals, outputs, expected) = terminal_seal_cases(txid(witness_nonce));
        let bundle = seal_bundle(contract_id, &seals, 0);
        let bundle_id = bundle.bundle_id();
        let fascia = Fascia::new(
            seal_witness(contract_id, bundle_id, witness_nonce),
            NonEmptyOrdMap::with_key_value(contract_id, bundle),
        );

        let consignment = stock
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

    /// Test terminal collection in stock.consign_operations
    ///
    /// Each of the three bundles is closed by a different witness TX and all three seals are
    /// requested as outputs, so every seal may only be resolved against the witness of the
    /// bundle holding it: the first two are witness-vout seals sharing a vout on
    /// distinct witnesses, the third sits on a pre-existing UTXO (`TxPtr::Txid`)
    #[test]
    fn terminal_seals_across_multiple_witnesses() {
        let mut stock = open_in_memory().unwrap();
        let contract_id = seed_contract(&mut stock);
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

        let consignment = stock
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
}
