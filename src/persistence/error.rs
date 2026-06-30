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

//! Error taxonomy for [`Stock`](super::Stock): the top-level [`StockError`],
//! the input-error families ([`ConsignError`]/[`ComposeError`]/[`FasciaError`]/
//! [`InputError`]) and the storage-consistency errors ([`Inconsistency`]/
//! [`DataError`]).

use std::convert::Infallible;
use std::error::Error;

use aluvm::library::LibId;
use amplify::confinement;
use rgb::bitcoin::{OutPoint as Outpoint, Txid};
use rgb::commit_verify::mpc;
use rgb::seals::txout::CloseMethod;
use rgb::validation::{SchemaDefError, WitnessResolverError};
use rgb::{AssignmentType, BundleId, ContractId, OpId, Opout, SchemaId, UnrelatedTransition};
use strict_types::typesys::UnknownType;

use super::RgbStore;
use crate::containers::SealWitnessMergeError;
use crate::contract::{BuilderError, ContractError, LinkError};
use crate::MergeRevealError;

/// Failure of a contract-state read.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum ContractStateError<E: Error> {
    /// Data-access (storage) error.
    #[from]
    Store(E),

    /// state of {0} does not decode as the family it is filed under.
    Decode(Opout),
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum StockError<S: RgbStore, E: Error = Infallible> {
    /// schema {0} is not imported; import its schema definition first.
    SchemaNotImported(SchemaId),

    InvalidInput(E),

    Resolver(String),

    /// Data-access (storage) error.
    Store(S::Error),

    /// Contract-state read error: the store answered, but what it holds could
    /// not be turned into state.
    #[from]
    State(ContractStateError<S::Error>),

    #[from]
    #[display(doc_comments)]
    /// {0}
    ///
    /// It may happen due to an RGB ops library bug, or indicate internal
    /// inconsistency and compromised data storage.
    Inconsistency(Inconsistency),

    #[from]
    #[from(UnknownType)]
    #[from(SealWitnessMergeError)]
    #[from(mpc::InvalidProof)]
    Data(DataError),

    /// valid (non-archived) witness is absent in the list of witnesses for a
    /// state transition bundle.
    AbsentValidWitness,

    /// Unable to sort bundles because of data inconsistency.
    BundlesInconsistency,

    /// a store transaction is already open: store transactions do not nest.
    ///
    /// It indicates an RGB ops library bug: a mutator running inside a unit of
    /// work called another one which opens its own.
    NestedTransaction,

    /// witness {0} can't be resolved: {1}
    WitnessUnresolved(Txid, WitnessResolverError),

    #[from]
    /// contract link is not valid: {1}
    ContractLinkError(LinkError),

    #[from]
    #[display(inner)]
    Contract(ContractError),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ConsignError {
    /// unable to construct consignment: too many bundles carry terminals.
    TooManyTerminalBundles,

    /// unable to construct consignment: too many terminal seals for a bundle.
    TooManyTerminalSeals,

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

    /// none of the transitions of bundle {0} is requested by the consignment.
    NoRequestedTransition(BundleId),
}

impl<S: RgbStore> From<ConsignError> for StockError<S, ConsignError> {
    fn from(err: ConsignError) -> Self { Self::InvalidInput(err) }
}

impl<S: RgbStore> From<MergeRevealError> for StockError<S, ConsignError> {
    fn from(err: MergeRevealError) -> Self { Self::InvalidInput(err.into()) }
}

impl<S: RgbStore> From<UnrelatedTransition> for StockError<S, ConsignError> {
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

impl<S: RgbStore> From<ComposeError> for StockError<S, ComposeError> {
    fn from(err: ComposeError) -> Self { Self::InvalidInput(err) }
}

impl<S: RgbStore> From<BuilderError> for StockError<S, ComposeError> {
    fn from(err: BuilderError) -> Self { Self::InvalidInput(err.into()) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum FasciaError {
    /// bundle {1} for contract {0} contains invalid transition input map.
    InvalidBundle(ContractId, BundleId),
}

impl<S: RgbStore> From<FasciaError> for StockError<S, FasciaError> {
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
    (@impl $err1:ty, $err2:ty, $e:ident => $conv:expr) => {
        impl<S: RgbStore> From<StockError<S, $err1>> for StockError<S, $err2> {
            fn from(err: StockError<S, $err1>) -> Self {
                match err {
                    StockError::InvalidInput($e) => $conv,
                    StockError::Resolver(e) => StockError::Resolver(e),
                    StockError::Store(e) => StockError::Store(e),
                    StockError::State(e) => StockError::State(e),
                    StockError::AbsentValidWitness => StockError::AbsentValidWitness,
                    StockError::BundlesInconsistency => StockError::BundlesInconsistency,
                    StockError::NestedTransaction => StockError::NestedTransaction,
                    StockError::Data(e) => StockError::Data(e),
                    StockError::Inconsistency(e) => StockError::Inconsistency(e),
                    StockError::WitnessUnresolved(id, e) => StockError::WitnessUnresolved(id, e),
                    StockError::ContractLinkError(e) => StockError::ContractLinkError(e),
                    StockError::SchemaNotImported(id) => StockError::SchemaNotImported(id),
                    StockError::Contract(e) => StockError::Contract(e),
                }
            }
        }
    };
    (Infallible, $err2:ty) => {
        stock_err_conv!(@impl Infallible, $err2, e => match e {});
    };
    ($err1:ty, $err2:ty) => {
        stock_err_conv!(@impl $err1, $err2, e => StockError::InvalidInput(e.into()));
    };
}

stock_err_conv!(Infallible, ComposeError);
stock_err_conv!(Infallible, ConsignError);
stock_err_conv!(Infallible, FasciaError);
stock_err_conv!(Infallible, InputError);
stock_err_conv!(ComposeError, InputError);
stock_err_conv!(ConsignError, InputError);
stock_err_conv!(FasciaError, InputError);

pub type StockErrorAll<S> = StockError<S, InputError>;

/// An internal data inconsistency: a reference is missing or contradictory.
///
/// These should never happen in normal operation; they indicate either an
/// RGB-ops bug or corrupted/compromised storage.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Inconsistency {
    /// contract {0} is unknown. Probably you haven't imported the contract yet.
    ContractAbsent(ContractId),

    /// schema {0} is unknown.
    SchemaAbsent(SchemaId),

    /// library {0} is unknown; perhaps you need to import it first.
    LibAbsent(LibId),

    /// transition {0} is absent.
    OperationAbsent(OpId),

    /// information about witness {0} is absent.
    WitnessAbsent(Txid),

    /// witness {0} for the bundle {1} misses contract {2} information in {3} anchor.
    WitnessMissesContract(Txid, BundleId, ContractId, CloseMethod),

    /// bundle {0} is absent.
    BundleAbsent(BundleId),

    /// bundle matching state transition {0} is absent in the store.
    OpBundleAbsent(OpId),

    /// outpoint {0} is not part of the contract {1}.
    OutpointUnknown(Outpoint, ContractId),

    /// store already contains information about bundle {bundle_id} which
    /// specifies contract {present} instead of contract {expected}.
    DistinctBundleContract {
        bundle_id: BundleId,
        present: ContractId,
        expected: ContractId,
    },

    /// store already contains information about operation {opid} which
    /// specifies bundle {present} instead of bundle {expected}.
    DistinctBundleOp {
        opid: OpId,
        present: BundleId,
        expected: BundleId,
    },

    /// contract id for bundle {0} is not known.
    BundleContractUnknown(BundleId),

    /// absent information about witness for bundle {0}.
    BundleWitnessUnknown(BundleId),
}

/// A malformed-data error: stored or incoming data could not be encoded,
/// decoded, merged, or otherwise made sense of.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DataError {
    /// the schema definition of {0} does not verify. {1}
    SchemaDef(SchemaId, Box<SchemaDefError>),

    /// schema {0} uses too many AluVM libraries.
    TooManyLibs(SchemaId),

    /// schema {0} is defined by too many strict type libraries.
    TooManyTypeLibs(SchemaId),

    #[from]
    #[display(inner)]
    UnknownType(UnknownType),

    #[from]
    #[display(inner)]
    Anchor(mpc::InvalidProof),

    #[from]
    #[display(inner)]
    Merge(SealWitnessMergeError),

    #[from]
    #[display(inner)]
    MergeReveal(MergeRevealError),

    #[from]
    #[display(inner)]
    Confinement(confinement::Error),
}
