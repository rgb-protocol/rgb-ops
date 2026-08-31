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
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Debug;

use amplify::confinement::LargeOrdSet;
use rgb::validation::{ResolveWitness, WitnessOrdProvider, WitnessResolverError};
use rgb::vm::{ContractStateAccess, WitnessOrd};
use rgb::{
    BundleId, ContractId, Genesis, KnownTransition, OpId, RevealedData, RevealedValue, Schema,
    SchemaId, Transition, TransitionBundle, Txid, VoidState,
};

use crate::containers::ConsignmentExt;
use crate::contract::OutputAssignment;
use crate::persistence::StoreTransaction;

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum StateError<P: StateProvider> {
    /// Connectivity errors which may be recoverable and temporary.
    ReadProvider(<P as StateReadProvider>::Error),

    /// Connectivity errors which may be recoverable and temporary.
    WriteProvider(<P as StateWriteProvider>::Error),

    /// witness {0} can't be resolved: {1}
    #[display(doc_comments)]
    Resolver(Txid, WitnessResolverError),

    /// valid (non-archived) witness is absent in the list of witnesses for a
    /// state transition bundle.
    AbsentValidWitness,

    /// {0}
    ///
    /// It may happen due to RGB ops library bug, or indicate internal
    /// stash inconsistency and compromised stash data storage.
    #[from]
    #[display(doc_comments)]
    Inconsistency(StateInconsistency),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum StateInconsistency {
    /// contract state {0} is not known.
    UnknownContract(ContractId),
    /// a witness {0} is absent from the state data.
    AbsentWitness(Txid),
}

#[derive(Debug)]
pub struct State<P: StateProvider> {
    provider: P,
}

impl<P: StateProvider> Default for State<P>
where P: Default
{
    fn default() -> Self {
        Self {
            provider: default!(),
        }
    }
}

impl<P: StateProvider> State<P> {
    pub(super) fn new(provider: P) -> Self { Self { provider } }

    #[doc(hidden)]
    pub fn as_provider(&self) -> &P { &self.provider }

    #[doc(hidden)]
    pub(super) fn as_provider_mut(&mut self) -> &mut P { &mut self.provider }

    #[inline]
    pub fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<P::ContractRead<'_>, StateError<P>> {
        self.provider
            .contract_state(contract_id)
            .map_err(StateError::ReadProvider)
    }

    pub fn select_valid_witness(
        &self,
        witness_ids: impl IntoIterator<Item = impl Borrow<Txid>>,
    ) -> Result<(Txid, WitnessOrd), StateError<P>> {
        let mut best_candidate = None;
        for id in witness_ids {
            let id = *id.borrow();
            let ord = self
                .as_provider()
                .witness_ord(id)
                .map_err(StateError::ReadProvider)?
                .ok_or(StateInconsistency::AbsentWitness(id))?;
            best_candidate = match best_candidate {
                Some((_, curr_ord)) if ord < curr_ord => Some((id, ord)),
                None => Some((id, ord)),
                _ => best_candidate,
            };
        }

        let (best_id, best_ord) = best_candidate.expect("one witness ID should always be there");
        if best_ord == WitnessOrd::Archived {
            Err(StateError::AbsentValidWitness)
        } else {
            Ok((best_id, best_ord))
        }
    }

    pub fn update_from_bundle<WP: WitnessOrdProvider>(
        &mut self,
        contract_id: ContractId,
        bundle: &TransitionBundle,
        witness_id: Txid,
        witness_ord_provider: &WP,
    ) -> Result<(), StateError<P>> {
        let mut updater = self
            .as_provider_mut()
            .update_contract(contract_id)
            .map_err(StateError::WriteProvider)?
            .ok_or(StateInconsistency::UnknownContract(contract_id))?;
        let bundle_id = bundle.bundle_id();
        for KnownTransition { transition, .. } in &bundle.known_transitions {
            let ord = witness_ord_provider
                .witness_ord(witness_id)
                .map_err(|e| StateError::Resolver(witness_id, e))?;
            updater
                .add_transition(transition, witness_id, ord, bundle_id)
                .map_err(StateError::WriteProvider)?;
        }
        Ok(())
    }

    pub fn update_from_consignment<R: ResolveWitness>(
        &mut self,
        consignment: impl ConsignmentExt,
        schema: &Schema,
        resolver: R,
    ) -> Result<(), StateError<P>> {
        let mut state = self
            .as_provider_mut()
            .register_contract(schema, consignment.genesis())
            .map_err(StateError::WriteProvider)?;
        for witness_bundle in consignment.bundled_witnesses() {
            let bundle = witness_bundle.bundle();
            let bundle_id = bundle.bundle_id();
            for KnownTransition { transition, .. } in &bundle.known_transitions {
                let witness_id = witness_bundle.witness_id();
                let witness_ord = resolver
                    .resolve_witness(witness_id)
                    .map_err(|e| StateError::Resolver(witness_id, e))?
                    .witness_ord();

                state
                    .add_transition(transition, witness_id, witness_ord, bundle_id)
                    .map_err(StateError::WriteProvider)?;
            }
        }

        Ok(())
    }

    pub fn upsert_witness(
        &mut self,
        witness_id: Txid,
        witness_ord: WitnessOrd,
    ) -> Result<(), StateError<P>> {
        self.provider
            .upsert_witness(witness_id, witness_ord)
            .map_err(StateError::WriteProvider)
    }

    pub fn update_op(&mut self, opid: OpId, valid: bool) -> Result<(), StateError<P>> {
        self.provider
            .update_op(opid, valid)
            .map_err(StateError::WriteProvider)
    }
}

impl<P: StateProvider> StoreTransaction for State<P> {
    type TransactionErr = StateError<P>;

    fn begin_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .begin_transaction()
            .map_err(StateError::WriteProvider)
    }

    fn commit_transaction(&mut self) -> Result<(), Self::TransactionErr> {
        self.provider
            .commit_transaction()
            .map_err(StateError::WriteProvider)
    }

    fn rollback_transaction(&mut self) { self.provider.rollback_transaction() }
}

pub trait StateProvider: Debug + StateReadProvider + StateWriteProvider {}

pub trait StateReadProvider {
    type ContractRead<'a>: ContractStateRead
    where Self: 'a;
    type Error: Clone + Eq + Error;

    // FIXME: this should be reconsidered in a db context, very inefficient
    fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<Self::ContractRead<'_>, Self::Error>;

    fn witness_ord(&self, id: Txid) -> Result<Option<WitnessOrd>, Self::Error>;
    fn all_witness_ords(&self) -> Result<BTreeMap<Txid, WitnessOrd>, Self::Error>;

    fn invalid_ops(&self) -> Result<LargeOrdSet<OpId>, Self::Error>;
}

pub trait StateWriteProvider {
    type ContractWrite<'a>: ContractStateWrite<Error = Self::Error>
    where Self: 'a;
    type Error: Error;

    /// Begins a storage transaction. Default is a no-op; see
    /// [`StashWriteProvider::begin_transaction`](super::StashWriteProvider::begin_transaction).
    fn begin_transaction(&mut self) -> Result<(), Self::Error> { Ok(()) }
    /// Commits the storage transaction (default no-op).
    fn commit_transaction(&mut self) -> Result<(), Self::Error> { Ok(()) }
    /// Rolls back the storage transaction (default no-op).
    fn rollback_transaction(&mut self) {}

    fn register_contract(
        &mut self,
        schema: &Schema,
        genesis: &Genesis,
    ) -> Result<Self::ContractWrite<'_>, Self::Error>;

    fn update_contract(
        &mut self,
        contract_id: ContractId,
    ) -> Result<Option<Self::ContractWrite<'_>>, Self::Error>;

    fn upsert_witness(
        &mut self,
        witness_id: Txid,
        witness_ord: WitnessOrd,
    ) -> Result<(), Self::Error>;

    fn update_op(&mut self, opid: OpId, valid: bool) -> Result<(), Self::Error>;
}

pub trait ContractStateRead: ContractStateAccess {
    type Error: Error;

    fn contract_id(&self) -> ContractId;
    fn schema_id(&self) -> SchemaId;
    fn witness_ord(&self, witness_id: Txid) -> Option<WitnessOrd>;
    fn rights_all(
        &self,
    ) -> impl Iterator<Item = Result<OutputAssignment<VoidState>, Self::Error>> + '_;
    fn fungible_all(
        &self,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedValue>, Self::Error>> + '_;
    fn data_all(
        &self,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedData>, Self::Error>> + '_;
}

pub trait ContractStateWrite {
    type Error: Error;

    fn add_genesis(&mut self, genesis: &Genesis) -> Result<(), Self::Error>;

    fn add_transition(
        &mut self,
        transition: &Transition,
        witness_id: Txid,
        witness_ord: WitnessOrd,
        bundle_id: BundleId,
    ) -> Result<(), Self::Error>;
}
