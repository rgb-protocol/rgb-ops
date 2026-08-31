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
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use amplify::confinement::{LargeOrdSet, TinyOrdMap};
use amplify::num::u24;
use amplify::Wrapper;
use rgb::bitcoin::{OutPoint as Outpoint, Txid};
use rgb::vm::{
    ContractStateAccess, GlobalOrd, GlobalStateEntry, GlobalsIter, UnknownGlobalStateType,
    WitnessOrd,
};
use rgb::{
    AssignmentType, Assignments, BundleId, ContractId, ExposedSeal, FungibleState, Genesis,
    GenesisSeal, GlobalState, GlobalStateType, GraphSeal, OpId, Operation, Opout, OutputSeal,
    RevealedData, RevealedValue, Schema, SchemaId, Transition, TypedAssigns, VoidState, Vout,
};
use strict_encoding::StrictDumb;

use super::{dec, enc, lock, SharedDb, SqlError};
use crate::contract::{GlobalOut, KnownState, OpWitness, OutputAssignment};
use crate::persistence::{
    ContractStateRead, ContractStateWrite, StateProvider, StateReadProvider, StateWriteProvider,
};

// ─── global state iterator ──────────────────────────────────────────────────

struct SqlGlobalIter {
    values: Vec<Rc<GlobalStateEntry>>,
    idx: usize,
}

impl SqlGlobalIter {
    fn new(mut entries: Vec<(GlobalOrd, RevealedData)>, limit: u32) -> Self {
        let mut values: Vec<Rc<GlobalStateEntry>> = entries
            .drain(..)
            .take(limit as usize)
            .map(|(ord, data)| Rc::new(GlobalStateEntry::new(ord, data)))
            .collect();
        values.sort();
        values.reverse();
        Self { values, idx: 0 }
    }
}

impl Iterator for SqlGlobalIter {
    type Item = Rc<GlobalStateEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.values.get(self.idx)?.clone();
        self.idx += 1;
        Some(entry)
    }

    fn count(self) -> usize { self.values.len() }
}

impl GlobalsIter for SqlGlobalIter {
    fn at_depth(&self, depth: usize) -> Option<Self::Item> { self.values.get(depth).cloned() }
}

// ─── reader ─────────────────────────────────────────────────────────────────

/// Contract state reader backed by relational tables.
///
/// `witness_filter` and `invalid_ops` are pre-loaded once at construction;
/// all other data is queried on demand from `assignment` / `global_state`.
pub struct SqlContractReader {
    db: SharedDb,
    contract_id: ContractId,
    schema_id: SchemaId,
    witness_filter: HashMap<Txid, WitnessOrd>,
    invalid_ops: BTreeSet<OpId>,
    global_type_limits: TinyOrdMap<GlobalStateType, u24>,
}

impl std::fmt::Debug for SqlContractReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SqlContractReader({})", self.contract_id)
    }
}

impl SqlContractReader {
    fn cid(&self) -> Vec<u8> { enc(&self.contract_id).expect("contract_id is always encodable") }

    /// Decode raw row columns into an `OutputAssignment<State>`.
    #[allow(clippy::too_many_arguments)]
    fn decode_assignment_row<State: strict_encoding::StrictDecode + KnownState>(
        type_id_i64: i64,
        op_id_blob: Vec<u8>,
        output_no: i64,
        seal_txid_blob: Vec<u8>,
        seal_vout: i64,
        witness_txid: Option<Vec<u8>>,
        bundle_id: Option<Vec<u8>>,
        value_blob: Vec<u8>,
    ) -> Result<OutputAssignment<State>, SqlError> {
        let opid = dec::<OpId>(&op_id_blob)?;
        let ty = AssignmentType::with(type_id_i64 as u16);
        let opout = Opout::new(opid, ty, output_no as u16);
        let seal =
            OutputSeal::with(dec::<Txid>(&seal_txid_blob)?, Vout::from_u32(seal_vout as u32));
        let state = dec::<State>(&value_blob)?;
        let witness = witness_txid.map(|b| dec::<Txid>(&b)).transpose()?;
        let bundle = bundle_id.map(|b| dec::<BundleId>(&b)).transpose()?;
        Ok(OutputAssignment {
            opout,
            seal,
            state,
            witness,
            bundle_id: bundle,
        })
    }

    fn check_row_valid(&self, witness_txid: &Option<Vec<u8>>, op_id: &[u8]) -> bool {
        let witness_ok = match witness_txid {
            None => true,
            Some(b) => match dec::<Txid>(b) {
                Ok(id) => {
                    !matches!(self.witness_filter.get(&id), None | Some(WitnessOrd::Archived))
                }
                Err(_) => false,
            },
        };
        let op_ok = match dec::<OpId>(op_id) {
            Ok(id) => !self.invalid_ops.contains(&id),
            Err(_) => false,
        };
        witness_ok && op_ok
    }

    fn fetch_fungibles_by_outpoint(
        &self,
        ty: AssignmentType,
        outpoint: Outpoint,
    ) -> Vec<OutputAssignment<RevealedValue>> {
        let db = match lock(&self.db) {
            Ok(d) => d,
            Err(_) => return vec![],
        };
        let cid = self.cid();
        let txid_blob = match enc(&outpoint.txid) {
            Ok(b) => b,
            Err(_) => return vec![],
        };
        let vout = i64::from(outpoint.vout);
        let type_id = i64::from(ty.into_inner());
        let mut stmt = match db.conn.prepare_cached(
            "SELECT type_id, op_id, output_no, seal_txid, seal_vout, witness_txid, bundle_id, \
             value_blob FROM assignment WHERE contract_id=?1 AND state_type='F' AND type_id=?2 \
             AND seal_txid=?3 AND seal_vout=?4",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        stmt.query_map(rusqlite::params![&cid, type_id, &txid_blob, vout], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        })
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|r| r.ok())
        .filter_map(|(tid, op, no, stxid, svout, wtxid, bid, val)| {
            Self::decode_assignment_row(tid, op, no, stxid, svout, wtxid, bid, val).ok()
        })
        .filter(|a| a.check_witness(&self.witness_filter))
        .filter(|a| a.check_op(&self.invalid_ops))
        .collect()
    }

    fn fetch_data_by_outpoint(
        &self,
        ty: AssignmentType,
        outpoint: Outpoint,
    ) -> Vec<OutputAssignment<RevealedData>> {
        let db = match lock(&self.db) {
            Ok(d) => d,
            Err(_) => return vec![],
        };
        let cid = self.cid();
        let txid_blob = match enc(&outpoint.txid) {
            Ok(b) => b,
            Err(_) => return vec![],
        };
        let vout = i64::from(outpoint.vout);
        let type_id = i64::from(ty.into_inner());
        let mut stmt = match db.conn.prepare_cached(
            "SELECT type_id, op_id, output_no, seal_txid, seal_vout, witness_txid, bundle_id, \
             value_blob FROM assignment WHERE contract_id=?1 AND state_type='D' AND type_id=?2 \
             AND seal_txid=?3 AND seal_vout=?4",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        stmt.query_map(rusqlite::params![&cid, type_id, &txid_blob, vout], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        })
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|r| r.ok())
        .filter_map(|(tid, op, no, stxid, svout, wtxid, bid, val)| {
            Self::decode_assignment_row(tid, op, no, stxid, svout, wtxid, bid, val).ok()
        })
        .filter(|a| a.check_witness(&self.witness_filter))
        .filter(|a| a.check_op(&self.invalid_ops))
        .collect()
    }

    fn count_rights_by_outpoint(&self, ty: AssignmentType, outpoint: Outpoint) -> u32 {
        let db = match lock(&self.db) {
            Ok(d) => d,
            Err(_) => return 0,
        };
        let cid = self.cid();
        let txid_blob = match enc(&outpoint.txid) {
            Ok(b) => b,
            Err(_) => return 0,
        };
        let vout = i64::from(outpoint.vout);
        let type_id = i64::from(ty.into_inner());
        let mut stmt = match db.conn.prepare_cached(
            "SELECT witness_txid, op_id FROM assignment WHERE contract_id=?1 AND state_type='R' \
             AND type_id=?2 AND seal_txid=?3 AND seal_vout=?4",
        ) {
            Ok(s) => s,
            Err(_) => return 0,
        };
        stmt.query_map(rusqlite::params![&cid, type_id, &txid_blob, vout], |row| {
            Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|r| r.ok())
        .filter(|(wtxid, opid)| self.check_row_valid(wtxid, opid))
        .count() as u32
    }

    fn fetch_all_assignments<State: strict_encoding::StrictDecode + KnownState>(
        &self,
        state_type: &str,
    ) -> Vec<OutputAssignment<State>> {
        let db = match lock(&self.db) {
            Ok(d) => d,
            Err(_) => return vec![],
        };
        let cid = self.cid();
        let mut stmt = match db.conn.prepare_cached(
            "SELECT type_id, op_id, output_no, seal_txid, seal_vout, witness_txid, bundle_id, \
             value_blob FROM assignment WHERE contract_id=?1 AND state_type=?2",
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        stmt.query_map(rusqlite::params![&cid, state_type], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        })
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|r| r.ok())
        .filter_map(|(tid, op, no, stxid, svout, wtxid, bid, val)| {
            Self::decode_assignment_row(tid, op, no, stxid, svout, wtxid, bid, val).ok()
        })
        .filter(|a| a.check_witness(&self.witness_filter))
        .filter(|a| a.check_op(&self.invalid_ops))
        .collect()
    }

    fn fetch_global_by_type(
        &self,
        ty: GlobalStateType,
    ) -> Result<(Vec<(GlobalOrd, RevealedData)>, u32), UnknownGlobalStateType> {
        let limit = self
            .global_type_limits
            .get(&ty)
            .ok_or(UnknownGlobalStateType(ty))?
            .to_u32();
        let db = match lock(&self.db) {
            Ok(d) => d,
            Err(_) => return Ok((vec![], limit)),
        };
        let cid = self.cid();
        let type_id = i64::from(ty.into_inner());
        let mut stmt = match db.conn.prepare_cached(
            "SELECT out_blob, value_blob FROM global_state WHERE contract_id=?1 AND type_id=?2",
        ) {
            Ok(s) => s,
            Err(_) => return Ok((vec![], limit)),
        };
        let entries: Vec<(GlobalOrd, RevealedData)> = stmt
            .query_map(rusqlite::params![&cid, type_id], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|r| r.ok())
            .filter_map(|(out_blob, val_blob)| {
                let out = dec::<GlobalOut>(&out_blob).ok()?;
                let data = dec::<RevealedData>(&val_blob).ok()?;
                let ord = match out.op_witness {
                    OpWitness::Genesis => GlobalOrd::genesis(out.index),
                    OpWitness::Transition(id, wty) => {
                        let ord = self.witness_filter.get(&id)?;
                        if *ord == WitnessOrd::Archived {
                            return None;
                        }
                        GlobalOrd::transition(out.opid, out.index, wty, out.nonce, *ord)
                    }
                };
                Some((ord, data))
            })
            .collect();
        Ok((entries, limit))
    }
}

impl ContractStateAccess for SqlContractReader {
    fn global(
        &self,
        ty: GlobalStateType,
    ) -> Result<impl GlobalsIter<Item = impl Borrow<GlobalStateEntry>>, UnknownGlobalStateType>
    {
        let (entries, limit) = self.fetch_global_by_type(ty)?;
        Ok(SqlGlobalIter::new(entries, limit))
    }

    fn rights(&self, outpoint: Outpoint, ty: AssignmentType) -> u32 {
        self.count_rights_by_outpoint(ty, outpoint)
    }

    fn fungible(
        &self,
        outpoint: Outpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = FungibleState> {
        self.fetch_fungibles_by_outpoint(ty, outpoint)
            .into_iter()
            .map(|a| a.state.into())
    }

    fn data(
        &self,
        outpoint: Outpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = impl Borrow<RevealedData>> {
        self.fetch_data_by_outpoint(ty, outpoint)
            .into_iter()
            .map(|a| a.state)
    }
}

impl ContractStateRead for SqlContractReader {
    type Error = SqlError;

    fn contract_id(&self) -> ContractId { self.contract_id }

    fn schema_id(&self) -> SchemaId { self.schema_id }

    fn witness_ord(&self, witness_id: Txid) -> Option<WitnessOrd> {
        self.witness_filter.get(&witness_id).copied()
    }

    fn rights_all(
        &self,
    ) -> impl Iterator<Item = Result<OutputAssignment<VoidState>, Self::Error>> + '_ {
        self.fetch_all_assignments::<VoidState>("R")
            .into_iter()
            .map(Ok)
    }

    fn fungible_all(
        &self,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedValue>, Self::Error>> + '_ {
        self.fetch_all_assignments::<RevealedValue>("F")
            .into_iter()
            .map(Ok)
    }

    fn data_all(
        &self,
    ) -> impl Iterator<Item = Result<OutputAssignment<RevealedData>, Self::Error>> + '_ {
        self.fetch_all_assignments::<RevealedData>("D")
            .into_iter()
            .map(Ok)
    }
}

// ─── provider ───────────────────────────────────────────────────────────────

/// SQLite-backed implementation of the state provider.
///
/// Contract state is stored relationally across `assignment`, `global_state`,
/// and `contract_meta` tables, enabling SQL-level filtering by outpoint, type,
/// witness and bundle validity.
#[derive(Clone, Debug)]
pub struct SqlState {
    db: SharedDb,
}

impl SqlState {
    pub(super) fn new(db: SharedDb) -> Self { Self { db } }
}

impl StateProvider for SqlState {}

impl StateReadProvider for SqlState {
    type ContractRead<'a> = SqlContractReader;
    type Error = SqlError;

    fn contract_state(
        &self,
        contract_id: ContractId,
    ) -> Result<Self::ContractRead<'_>, Self::Error> {
        let key = enc(&contract_id)?;
        let db = lock(&self.db)?;
        let (schema_id_blob, limits_blob): (Vec<u8>, Vec<u8>) = {
            let mut stmt = db.conn.prepare_cached(
                "SELECT schema_id, limits_blob FROM contract_meta WHERE contract_id=?1",
            )?;
            match stmt
                .query_row([&key], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))
            {
                Ok(pair) => pair,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Err(SqlError(format!("contract {contract_id} is unknown")));
                }
                Err(e) => return Err(e.into()),
            }
        };
        let schema_id = dec::<SchemaId>(&schema_id_blob)?;
        let global_type_limits = dec::<TinyOrdMap<GlobalStateType, u24>>(&limits_blob)?;

        let mut witness_filter = HashMap::new();
        {
            let mut stmt = db
                .conn
                .prepare_cached("SELECT txid, ord FROM witness_ord")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let txid_blob: Vec<u8> = row.get(0)?;
                let ord_blob: Vec<u8> = row.get(1)?;
                witness_filter.insert(dec::<Txid>(&txid_blob)?, dec::<WitnessOrd>(&ord_blob)?);
            }
        }
        let mut invalid_ops = BTreeSet::new();
        {
            let mut stmt = db.conn.prepare_cached("SELECT op_id FROM invalid_op")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let blob: Vec<u8> = row.get(0)?;
                invalid_ops.insert(dec::<OpId>(&blob)?);
            }
        }
        Ok(SqlContractReader {
            db: self.db.clone(),
            contract_id,
            schema_id,
            witness_filter,
            invalid_ops,
            global_type_limits,
        })
    }

    fn witness_ord(&self, id: Txid) -> Result<Option<WitnessOrd>, Self::Error> {
        let key = enc(&id)?;
        lock(&self.db)?
            .blob("SELECT ord FROM witness_ord WHERE txid = ?1", &key)?
            .map(|blob| dec(&blob))
            .transpose()
    }

    fn all_witness_ords(&self) -> Result<BTreeMap<Txid, WitnessOrd>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT txid, ord FROM witness_ord")?;
        let mut rows = stmt.query([])?;
        let mut ords = BTreeMap::new();
        loop {
            let Some(row) = rows.next()? else { break };
            let txid: Vec<u8> = row.get(0)?;
            let ord: Vec<u8> = row.get(1)?;
            ords.insert(dec::<Txid>(&txid)?, dec::<WitnessOrd>(&ord)?);
        }
        Ok(ords)
    }

    fn invalid_ops(&self) -> Result<LargeOrdSet<OpId>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached("SELECT op_id FROM invalid_op")?;
        let mut rows = stmt.query([])?;
        let mut ids = BTreeSet::new();
        loop {
            let Some(row) = rows.next()? else { break };
            let op_id: Vec<u8> = row.get(0)?;
            ids.insert(dec::<OpId>(&op_id)?);
        }
        Ok(LargeOrdSet::from_iter_checked(ids))
    }
}

impl StateWriteProvider for SqlState {
    type ContractWrite<'a> = SqlContractWriter;
    type Error = SqlError;

    #[inline]
    fn begin_transaction(&mut self) -> Result<(), Self::Error> { lock(&self.db)?.begin() }
    #[inline]
    fn commit_transaction(&mut self) -> Result<(), Self::Error> { lock(&self.db)?.commit() }
    #[inline]
    fn rollback_transaction(&mut self) {
        if let Ok(mut db) = self.db.lock() {
            db.rollback();
        }
    }

    fn register_contract(
        &mut self,
        schema: &Schema,
        genesis: &Genesis,
    ) -> Result<Self::ContractWrite<'_>, Self::Error> {
        let contract_id = genesis.contract_id();
        let limits: TinyOrdMap<GlobalStateType, u24> = TinyOrdMap::from_iter_checked(
            schema
                .global_types
                .iter()
                .map(|(ty, glob)| (*ty, glob.global_state_schema.max_items)),
        );
        lock(&self.db)?.conn.execute(
            "INSERT OR IGNORE INTO contract_meta (contract_id, schema_id, limits_blob) VALUES \
             (?1, ?2, ?3)",
            (enc(&contract_id)?, enc(&schema.schema_id())?, enc(&limits)?),
        )?;
        let mut writer = SqlContractWriter {
            db: self.db.clone(),
            contract_id,
        };
        writer.add_genesis(genesis)?;
        Ok(writer)
    }

    fn update_contract(
        &mut self,
        contract_id: ContractId,
    ) -> Result<Option<Self::ContractWrite<'_>>, Self::Error> {
        let key = enc(&contract_id)?;
        let exists =
            lock(&self.db)?.exists("SELECT 1 FROM contract_meta WHERE contract_id=?1", &key)?;
        if exists {
            Ok(Some(SqlContractWriter {
                db: self.db.clone(),
                contract_id,
            }))
        } else {
            Ok(None)
        }
    }

    fn upsert_witness(
        &mut self,
        witness_id: Txid,
        witness_ord: WitnessOrd,
    ) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT OR REPLACE INTO witness_ord (txid, ord) VALUES (?1, ?2)",
            (enc(&witness_id)?, enc(&witness_ord)?),
        )?;
        Ok(())
    }

    fn update_op(&mut self, opid: OpId, valid: bool) -> Result<(), Self::Error> {
        let key = enc(&opid)?;
        let db = lock(&self.db)?;
        if valid {
            db.conn
                .execute("DELETE FROM invalid_op WHERE op_id = ?1", (key,))?;
        } else {
            db.conn
                .execute("INSERT OR IGNORE INTO invalid_op (op_id) VALUES (?1)", (key,))?;
        }
        Ok(())
    }
}

// ─── writer ─────────────────────────────────────────────────────────────────

/// Contract state writer: inserts individual rows into `assignment` and
/// `global_state` on each operation, replacing the old whole-blob approach.
pub struct SqlContractWriter {
    db: SharedDb,
    contract_id: ContractId,
}

impl SqlContractWriter {
    fn insert_global_state(
        &self,
        opid: OpId,
        nonce: u64,
        op_witness: OpWitness,
        globals: &GlobalState,
    ) -> Result<(), SqlError> {
        let db = lock(&self.db)?;
        let cid = enc(&self.contract_id)?;
        for (ty, values) in globals {
            let type_id = i64::from((*ty).into_inner());
            for (idx, data) in values.iter().enumerate() {
                let out = GlobalOut {
                    index: idx as u16,
                    op_witness,
                    nonce,
                    opid,
                };
                db.conn.execute(
                    "INSERT OR IGNORE INTO global_state (contract_id, type_id, out_blob, \
                     value_blob) VALUES (?1, ?2, ?3, ?4)",
                    (&cid, type_id, enc(&out)?, enc(data)?),
                )?;
            }
        }
        Ok(())
    }

    fn insert_genesis_assignments(
        &self,
        opid: OpId,
        assignments: &Assignments<GenesisSeal>,
    ) -> Result<(), SqlError> {
        let db = lock(&self.db)?;
        let cid = enc(&self.contract_id)?;
        let opid_blob = enc(&opid)?;
        for (ty, typed) in assignments.iter() {
            let type_id = i64::from((*ty).into_inner());
            match typed {
                TypedAssigns::Declarative(assigns) => {
                    for (no, assign) in assigns.iter().enumerate() {
                        if let Some((seal, _)) = assign.to_revealed() {
                            let output_seal =
                                seal.to_output_seal().expect("genesis seal always has txid");
                            db.conn.execute(
                                "INSERT OR IGNORE INTO assignment (contract_id, state_type, \
                                 type_id, op_id, output_no, seal_txid, seal_vout, witness_txid, \
                                 bundle_id, value_blob) VALUES (?1, 'R', ?2, ?3, ?4, ?5, ?6, \
                                 NULL, NULL, ?7)",
                                (
                                    &cid,
                                    type_id,
                                    &opid_blob,
                                    no as i64,
                                    enc(&output_seal.txid)?,
                                    i64::from(output_seal.vout.to_u32()),
                                    enc(&VoidState::strict_dumb())?,
                                ),
                            )?;
                        }
                    }
                }
                TypedAssigns::Fungible(assigns) => {
                    for (no, assign) in assigns.iter().enumerate() {
                        if let Some((seal, state)) = assign.to_revealed() {
                            let output_seal =
                                seal.to_output_seal().expect("genesis seal always has txid");
                            db.conn.execute(
                                "INSERT OR IGNORE INTO assignment (contract_id, state_type, \
                                 type_id, op_id, output_no, seal_txid, seal_vout, witness_txid, \
                                 bundle_id, value_blob) VALUES (?1, 'F', ?2, ?3, ?4, ?5, ?6, \
                                 NULL, NULL, ?7)",
                                (
                                    &cid,
                                    type_id,
                                    &opid_blob,
                                    no as i64,
                                    enc(&output_seal.txid)?,
                                    i64::from(output_seal.vout.to_u32()),
                                    enc(&state)?,
                                ),
                            )?;
                        }
                    }
                }
                TypedAssigns::Structured(assigns) => {
                    for (no, assign) in assigns.iter().enumerate() {
                        if let Some((seal, state)) = assign.to_revealed() {
                            let output_seal =
                                seal.to_output_seal().expect("genesis seal always has txid");
                            db.conn.execute(
                                "INSERT OR IGNORE INTO assignment (contract_id, state_type, \
                                 type_id, op_id, output_no, seal_txid, seal_vout, witness_txid, \
                                 bundle_id, value_blob) VALUES (?1, 'D', ?2, ?3, ?4, ?5, ?6, \
                                 NULL, NULL, ?7)",
                                (
                                    &cid,
                                    type_id,
                                    &opid_blob,
                                    no as i64,
                                    enc(&output_seal.txid)?,
                                    i64::from(output_seal.vout.to_u32()),
                                    enc(&state)?,
                                ),
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn insert_transition_assignments(
        &self,
        opid: OpId,
        witness_id: Txid,
        bundle_id: BundleId,
        assignments: &Assignments<GraphSeal>,
    ) -> Result<(), SqlError> {
        let db = lock(&self.db)?;
        let cid = enc(&self.contract_id)?;
        let opid_blob = enc(&opid)?;
        let wtxid_blob = enc(&witness_id)?;
        let bid_blob = enc(&bundle_id)?;
        for (ty, typed) in assignments.iter() {
            let type_id = i64::from((*ty).into_inner());
            match typed {
                TypedAssigns::Declarative(assigns) => {
                    for (no, assign) in assigns.iter().enumerate() {
                        if let Some((seal, _)) = assign.to_revealed() {
                            let output_seal = seal.to_output_seal_or_default(witness_id);
                            db.conn.execute(
                                "INSERT OR IGNORE INTO assignment (contract_id, state_type, \
                                 type_id, op_id, output_no, seal_txid, seal_vout, witness_txid, \
                                 bundle_id, value_blob) VALUES (?1, 'R', ?2, ?3, ?4, ?5, ?6, ?7, \
                                 ?8, ?9)",
                                (
                                    &cid,
                                    type_id,
                                    &opid_blob,
                                    no as i64,
                                    enc(&output_seal.txid)?,
                                    i64::from(output_seal.vout.to_u32()),
                                    &wtxid_blob,
                                    &bid_blob,
                                    enc(&VoidState::strict_dumb())?,
                                ),
                            )?;
                        }
                    }
                }
                TypedAssigns::Fungible(assigns) => {
                    for (no, assign) in assigns.iter().enumerate() {
                        if let Some((seal, state)) = assign.to_revealed() {
                            let output_seal = seal.to_output_seal_or_default(witness_id);
                            db.conn.execute(
                                "INSERT OR IGNORE INTO assignment (contract_id, state_type, \
                                 type_id, op_id, output_no, seal_txid, seal_vout, witness_txid, \
                                 bundle_id, value_blob) VALUES (?1, 'F', ?2, ?3, ?4, ?5, ?6, ?7, \
                                 ?8, ?9)",
                                (
                                    &cid,
                                    type_id,
                                    &opid_blob,
                                    no as i64,
                                    enc(&output_seal.txid)?,
                                    i64::from(output_seal.vout.to_u32()),
                                    &wtxid_blob,
                                    &bid_blob,
                                    enc(&state)?,
                                ),
                            )?;
                        }
                    }
                }
                TypedAssigns::Structured(assigns) => {
                    for (no, assign) in assigns.iter().enumerate() {
                        if let Some((seal, state)) = assign.to_revealed() {
                            let output_seal = seal.to_output_seal_or_default(witness_id);
                            db.conn.execute(
                                "INSERT OR IGNORE INTO assignment (contract_id, state_type, \
                                 type_id, op_id, output_no, seal_txid, seal_vout, witness_txid, \
                                 bundle_id, value_blob) VALUES (?1, 'D', ?2, ?3, ?4, ?5, ?6, ?7, \
                                 ?8, ?9)",
                                (
                                    &cid,
                                    type_id,
                                    &opid_blob,
                                    no as i64,
                                    enc(&output_seal.txid)?,
                                    i64::from(output_seal.vout.to_u32()),
                                    &wtxid_blob,
                                    &bid_blob,
                                    enc(&state)?,
                                ),
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl ContractStateWrite for SqlContractWriter {
    type Error = SqlError;

    fn add_genesis(&mut self, genesis: &Genesis) -> Result<(), Self::Error> {
        let opid = genesis.id();
        self.insert_global_state(opid, genesis.nonce(), OpWitness::Genesis, genesis.globals())?;
        self.insert_genesis_assignments(opid, &genesis.assignments)
    }

    fn add_transition(
        &mut self,
        transition: &Transition,
        witness_id: Txid,
        witness_ord: WitnessOrd,
        bundle_id: BundleId,
    ) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT OR REPLACE INTO witness_ord (txid, ord) VALUES (?1, ?2)",
            (enc(&witness_id)?, enc(&witness_ord)?),
        )?;
        let opid = transition.id();
        let op_witness = OpWitness::Transition(witness_id, transition.transition_type);
        self.insert_global_state(opid, transition.nonce(), op_witness, transition.globals())?;
        self.insert_transition_assignments(opid, witness_id, bundle_id, &transition.assignments)
    }
}
