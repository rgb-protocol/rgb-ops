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

//! Contract-state reader built on top of an [`RgbStore`].
//!
//! Reads one contract's state out of a store: it decodes the stored values and
//! puts global state into the order a contract sees it in.
//!
//! Which rows count as state is left to the store, asked for as
//! [`Visibility::Valid`] rather than filtered here afterwards.
//!
//! Backend-agnostic: it only calls the [`RgbStore`] row accessors.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;

use rgb::bitcoin::Txid;
use rgb::vm::{GlobalOrd, GlobalStateEntry, GlobalsIter, UnknownGlobalStateType, WitnessOrd};
use rgb::{
    AssignmentType, BundleId, ContractId, GlobalStateType, Opout, OutputSeal, RevealedData,
    RevealedValue, Schema, SchemaId, VoidState,
};
use strict_encoding::StrictDecode;

use crate::contract::{
    global_ord, AllocatedState, ContractStateRead, GlobalOut, GlobalStateIter,
    GlobalStateReadError, KnownState, OpWitness, OutputAssignment,
};
use crate::persistence::codec::dec_opt;
use crate::persistence::{
    AllocKind, AllocSeal, AllocationFilter, AllocationRow, ContractStateError, RgbStore, Visibility,
};

// ----- shared allocation helpers ---------------------------------------------

/// Global-state entries of one type, with the per-type limit they are capped at.
type GlobalEntries = (Vec<(GlobalOrd, RevealedData)>, u32);

/// Decodes an allocation's opaque value blob under the state family it was
/// stored as.
///
/// A blob that does not decode is an error and not an absence: the row is on
/// file under a family whose state it does not hold, which is the store
/// contradicting itself and nothing a caller can carry on past.
pub(crate) fn decode_allocated<E: Error>(
    row: &AllocationRow,
) -> Result<AllocatedState, ContractStateError<E>> {
    Ok(match row.kind {
        AllocKind::Fungible => AllocatedState::Amount(
            dec_opt::<RevealedValue>(&row.value).ok_or(ContractStateError::Decode(row.opout))?,
        ),
        AllocKind::Structured => AllocatedState::Data(
            dec_opt::<RevealedData>(&row.value).ok_or(ContractStateError::Decode(row.opout))?,
        ),
        AllocKind::Declarative => AllocatedState::Void,
    })
}

/// The seal of a row read at an outpoint, which the store has resolved to that
/// outpoint.
pub(crate) fn resolved_at_outpoint(row: &AllocationRow) -> OutputSeal {
    row.seal
        .resolve(None)
        .expect("allocations read at an outpoint are resolved to it")
}

// ----- reader ---------------------------------------------------------------

/// One contract's computed state, read in full and owned.
///
/// Every accessor answers from this one copy, taken by a single pass over the
/// store inside one read transaction.
///
/// What that costs is worth stating plainly. A contract's whole state is held
/// in memory, and it is a snapshot: writes made after it was taken are not in
/// it, and a caller wanting to see them asks for a new one.
///
/// A seal on the witness transaction lands on a different outpoint under each
/// witness of its bundle, and is listed under every one of them that is not
/// archived: with the commitment transactions of a channel all carrying one
/// bundle, or a transaction and its fee-bumped replacement both pending, which
/// of them stands is not known until the ords say so. Filtering by owned
/// outpoints picks the right one, as a read at outpoints does
/// ([`Stock::contract_assignments_for`]); summing a listing without such a
/// filter counts the allocation once per witness.
///
/// [`Stock::contract_assignments_for`]: super::Stock::contract_assignments_for
#[derive(Clone, Debug)]
pub struct ContractStateSnapshot {
    contract_id: ContractId,
    schema_id: SchemaId,
    globals: BTreeMap<GlobalStateType, GlobalEntries>,
    rights: Vec<OutputAssignment<VoidState>>,
    fungibles: Vec<OutputAssignment<RevealedValue>>,
    data: Vec<OutputAssignment<RevealedData>>,
    witness_ords: BTreeMap<Txid, WitnessOrd>,
}

impl ContractStateSnapshot {
    /// Reads a contract's state in full.
    ///
    /// The caller holds a read transaction around this: the queries below are
    /// several, and a snapshot assembled from two states would defeat the point
    /// of taking one.
    pub(super) fn load<S: RgbStore>(
        store: &S,
        contract_id: ContractId,
        schema: &Schema,
    ) -> Result<Self, ContractStateError<S::Error>> {
        let mut global_rows = Vec::new();
        for (ty, details) in schema.global_types.iter() {
            let rows = store.globals(contract_id, *ty, Visibility::Valid)?;
            global_rows.push((*ty, rows, details.global_state_schema.max_items.to_u32()));
        }
        let valid = AllocationFilter::all(Visibility::Valid);
        let rights = load_allocations(store, contract_id, valid.kind(AllocKind::Declarative))?;
        let fungibles = load_allocations(store, contract_id, valid.kind(AllocKind::Fungible))?;
        let data = load_allocations(store, contract_id, valid.kind(AllocKind::Structured))?;

        // Every row names the bundle it came from; the witnesses of that bundle
        // it is listed under are ranked once here, for the whole snapshot,
        // instead of per row - and only for the bundles these rows name.
        let bundles: BTreeSet<BundleId> = global_rows
            .iter()
            .flat_map(|(_, rows, _)| rows.iter().filter_map(|r| r.bundle_id))
            .chain(rights.iter().filter_map(|a| a.bundle_id))
            .chain(fungibles.iter().filter_map(|a| a.bundle_id))
            .chain(data.iter().filter_map(|a| a.bundle_id))
            .collect();
        let witnesses = rank_witnesses(store, &bundles, Visibility::Valid)?;

        let globals = global_rows
            .into_iter()
            .map(|(ty, rows, limit)| {
                let entries = rows
                    .into_iter()
                    .filter_map(|row| {
                        let (op_witness, ord) = match (row.bundle_id, row.transition_type) {
                            (None, None) => (OpWitness::Genesis, None),
                            // a bundle resolving to no witness leaves the entry
                            // unorderable, which is what dropped it before too;
                            // global state is ordered by the first-ranked one
                            (Some(bundle_id), Some(tt)) => {
                                let (txid, ord) = *witnesses.get(&bundle_id)?.first()?;
                                (OpWitness::Transition(txid, tt), Some(ord))
                            }
                            _ => return None,
                        };
                        let out = GlobalOut {
                            index: row.index,
                            op_witness,
                            nonce: row.nonce,
                            opid: row.opid,
                        };
                        Some((global_ord(&out, ord)?, row.value))
                    })
                    .collect();
                (ty, (entries, limit))
            })
            .collect();

        Ok(Self {
            contract_id,
            schema_id: schema.schema_id(),
            globals,
            rights: attach_witnesses(rights, &witnesses),
            fungibles: attach_witnesses(fungibles, &witnesses),
            data: attach_witnesses(data, &witnesses),
            witness_ords: witnesses.into_values().flatten().collect(),
        })
    }
}

/// The witnesses anchoring a bundle, best-ranked first, each with its ord.
type RankedWitnesses = Vec<(Txid, WitnessOrd)>;

/// The witnesses anchoring each of `bundles`, ranked by [`WitnessOrd`] with
/// ties broken by txid, so that the first is the one a consignment carries the
/// bundle under (the choice `Stock::select_valid_witness` makes). Archived
/// witnesses are left out unless `visibility` is [`Visibility::All`]; one with
/// no ord stored is left out either way, and a bundle left with no witness is
/// absent.
///
/// Two batched queries for the whole snapshot rather than a pair per row: the
/// ranking is `Ord` on `WitnessPos`, which weighs layers against each other and
/// so has to be decided here rather than by a column order.
fn rank_witnesses<S: RgbStore>(
    store: &S,
    bundles: &BTreeSet<BundleId>,
    visibility: Visibility,
) -> Result<BTreeMap<BundleId, RankedWitnesses>, ContractStateError<S::Error>> {
    let by_bundle = store.witnesses_of_bundles(bundles)?;
    let all: BTreeSet<Txid> = by_bundle.values().flatten().copied().collect();
    let ords = store.witness_ords(&all)?;
    let listed =
        |ord: WitnessOrd| matches!(visibility, Visibility::All) || ord != WitnessOrd::Archived;
    Ok(by_bundle
        .into_iter()
        .filter_map(|(bundle_id, witnesses)| {
            let mut ranked: RankedWitnesses = witnesses
                .into_iter()
                .filter_map(|id| ords.get(&id).map(|ord| (id, *ord)))
                .filter(|&(_, ord)| listed(ord))
                .collect();
            if ranked.is_empty() {
                return None;
            }
            ranked.sort_by_key(|&(txid, ord)| (ord, txid));
            Some((bundle_id, ranked))
        })
        .collect())
}

/// An allocation as read, before the witness of its bundle is selected: until
/// then neither the witness it is reported under nor, for a seal on the witness
/// transaction, the outpoint it lands on is known.
struct PendingAllocation<State> {
    state: State,
    opout: Opout,
    seal: AllocSeal,
    bundle_id: Option<BundleId>,
}

/// Resolves each allocation against the witnesses of its bundle, now that the
/// snapshot's bundles have theirs ranked. An explicit seal is listed once,
/// under the witness ranking first. A seal on the witness transaction lands on
/// a different outpoint under each witness, and is listed once per witness:
/// which of them stands is not known until the ords tell them apart. One whose
/// bundle has no witness listed lands nowhere and is dropped; a valid bundle
/// always has one, so only [`Visibility::All`] reads can meet this.
fn attach_witnesses<State: KnownState>(
    rows: Vec<PendingAllocation<State>>,
    witnesses: &BTreeMap<BundleId, RankedWitnesses>,
) -> Vec<OutputAssignment<State>> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let ranked = row
            .bundle_id
            .and_then(|id| witnesses.get(&id))
            .map_or(&[][..], Vec::as_slice);
        if let Some(seal) = row.seal.resolve(None) {
            out.push(OutputAssignment {
                state: row.state,
                opout: row.opout,
                seal,
                witness: ranked.first().map(|&(txid, _)| txid),
                bundle_id: row.bundle_id,
            });
            continue;
        }
        out.extend(ranked.iter().map(|&(txid, _)| OutputAssignment {
            state: row.state.clone(),
            opout: row.opout,
            seal: OutputSeal::with(txid, row.seal.vout),
            witness: Some(txid),
            bundle_id: row.bundle_id,
        }));
    }
    out
}

/// Each allocation is left pending, since its witness is not known until the
/// bundles of the whole snapshot are resolved together.
fn load_allocations<S: RgbStore, State: StrictDecode + KnownState>(
    store: &S,
    contract_id: ContractId,
    filter: AllocationFilter<'_>,
) -> Result<Vec<PendingAllocation<State>>, ContractStateError<S::Error>> {
    store
        .allocations(contract_id, filter)?
        .into_iter()
        .map(|row| {
            Ok(PendingAllocation {
                state: dec_opt::<State>(&row.value).ok_or(ContractStateError::Decode(row.opout))?,
                opout: row.opout,
                seal: row.seal,
                bundle_id: row.bundle_id,
            })
        })
        .collect()
}

/// The allocations matching `filter`, each with the witness it is reported
/// under.
///
/// What [`ContractStateSnapshot`] does for a whole contract, over the rows the
/// filter matches.
pub(super) fn load_output_assignments<S: RgbStore, State: StrictDecode + KnownState>(
    store: &S,
    contract_id: ContractId,
    filter: AllocationFilter<'_>,
) -> Result<Vec<OutputAssignment<State>>, ContractStateError<S::Error>> {
    let rows = load_allocations::<S, State>(store, contract_id, filter)?;
    let bundles: BTreeSet<BundleId> = rows.iter().filter_map(|a| a.bundle_id).collect();
    let witnesses = rank_witnesses(store, &bundles, filter.visibility)?;
    Ok(attach_witnesses(rows, &witnesses))
}

/// The allocations of one family, narrowed to an assignment type when one is
/// asked for. Cloned out: the caller owns what it iterates, as it would from a
/// query.
fn narrowed<State: KnownState + Clone>(
    all: &[OutputAssignment<State>],
    type_id: Option<AssignmentType>,
) -> impl Iterator<Item = Result<OutputAssignment<State>, Infallible>> + '_ {
    all.iter()
        .filter(move |a| type_id.is_none_or(|ty| a.opout.ty == ty))
        .cloned()
        .map(Ok)
}

impl ContractStateRead for ContractStateSnapshot {
    /// Read from the store once, into memory: an accessor cannot fail.
    type Error = Infallible;

    fn global_all(
        &self,
        ty: GlobalStateType,
    ) -> Result<
        impl GlobalsIter<Item = impl Borrow<GlobalStateEntry>>,
        GlobalStateReadError<Self::Error>,
    > {
        let (entries, limit) = self
            .globals
            .get(&ty)
            .ok_or(GlobalStateReadError::UnknownType(UnknownGlobalStateType(ty)))?;
        Ok(GlobalStateIter::new(entries.clone(), *limit))
    }

    #[inline]
    fn contract_id(&self) -> ContractId { self.contract_id }

    #[inline]
    fn schema_id(&self) -> SchemaId { self.schema_id }

    #[inline]
    fn witness_ord(&self, witness_id: Txid) -> Result<Option<WitnessOrd>, Self::Error> {
        Ok(self.witness_ords.get(&witness_id).copied())
    }

    fn rights_all(
        &self,
        type_id: Option<AssignmentType>,
    ) -> impl Iterator<Item = Result<OutputAssignment<VoidState>, Self::Error>> + '_ {
        narrowed(&self.rights, type_id)
    }

    fn fungible_all(
        &self,
        type_id: Option<AssignmentType>,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedValue>, Self::Error>> + '_ {
        narrowed(&self.fungibles, type_id)
    }

    fn data_all(
        &self,
        type_id: Option<AssignmentType>,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedData>, Self::Error>> + '_ {
        narrowed(&self.data, type_id)
    }
}
