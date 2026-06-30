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

//! Single [`RgbStore`] implementation backed by one SQLite connection. Methods
//! are mechanical row access against the schema in [`super::schema`]; all RGB
//! semantics live in [`Stock`](crate::persistence::Stock).

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use aluvm::library::{Lib, LibId};
use amplify::Wrapper;
use rgb::bitcoin::{OutPoint as Outpoint, Transaction as Tx, Txid};
use rgb::commit_verify::Conceal;
use rgb::validation::DbcProof;
use rgb::vm::{WitnessOrd, WitnessPos};
use rgb::{
    AssignmentType, BundleId, ContractId, Genesis, GlobalStateType, GraphSeal, Layer1, OpId,
    Operation, Opout, RevealedData, Schema, SchemaId, SecretSeal, TransitionBundle, TransitionType,
    Vout,
};
use rusqlite::params_from_iter;
use rusqlite::types::Value;
use strict_types::{TypeLib, TypeLibId};

use super::{dec, dec_keyed, enc, load_all, lock, SharedDb, SqliteError};
use crate::containers::{SealWitness, SpvProof};
use crate::persistence::{
    AllocKind, AllocSeal, AllocationFilter, AllocationRow, AllocationWrite, GlobalStateRow,
    GlobalStateWrite, RgbStore, TxBegin, TxMode, Visibility,
};

/// Max bound parameters per `IN (...)` / `IN (VALUES ...)` query, keeping the
/// count well under SQLite's `SQLITE_MAX_VARIABLE_NUMBER` on large rescans.
const QUERY_CHUNK: usize = 400;

/// The `assignment` columns [`decode_alloc_row`] reads, in the order it reads
/// them. Anything a query selects on top of these comes after, so their indices
/// hold whichever query produced the row.
const ALLOC_COLS: &str = "SELECT a.type_id, a.opid, a.output_no, a.seal_txid, a.seal_vout, \
                          a.bundle_id, a.value_blob, a.state_type";

/// [`ALLOC_COLS`] for a seal on the witness transaction reached through
/// `bundle_witness bw`: the same columns, with the seal resolved to that
/// witness.
const WITNESS_ALLOC_COLS: &str = "SELECT a.type_id, a.opid, a.output_no, bw.txid, a.seal_vout, \
                                  a.bundle_id, a.value_blob, a.state_type";

/// Finds the allocations landing on the outpoints of CTE `q(txid, vout)`, with
/// `{narrow}`, `{vis}` and `{wvis}` to fill in. Two branches, one per way a seal
/// can name an outpoint: an explicit seal names it itself, a seal on the witness
/// transaction lands on it when `q.txid` is one of its bundle's witnesses - the
/// latter reached from the witness, through `idx_bundle_witness_txid` and
/// `idx_assignment_witness_seal`.
fn alloc_at_outpoints_sql(
    cols: &str,
    witness_cols: &str,
    narrow: &str,
    vis: &str,
    wvis: &str,
) -> String {
    format!(
        "{cols} FROM assignment a WHERE {narrow} a.seal_txid IS NOT NULL AND (a.seal_txid, \
         a.seal_vout) IN (SELECT txid, vout FROM q){vis} UNION ALL {witness_cols} FROM q JOIN \
         bundle_witness bw ON bw.txid = q.txid JOIN assignment a ON a.bundle_id = bw.bundle_id \
         WHERE {narrow} a.seal_txid IS NULL AND a.seal_vout = q.vout{wvis}"
    )
}

/// `witness_ord.status` values. Mirror the strict-encoding tag order of
/// [`WitnessOrd`], and `ARCHIVED` is the one the validity filter tests for, so
/// the mapping is part of the on-disk format and not an implementation detail.
const ORD_MINED: i64 = 0;
const ORD_TENTATIVE: i64 = 1;
const ORD_IGNORED: i64 = 2;
const ORD_ARCHIVED: i64 = 3;

/// The `WHERE` fragment restricting `assignment a` to the rows
/// [`Visibility::Valid`] admits: those whose bundle is anchored by at least one
/// witness which is not archived, produced by an operation not marked invalid.
/// Genesis rows have no bundle and are always visible.
///
/// The valid-bundle set is uncorrelated, so SQLite builds it once per query
/// rather than per row - asking per row costs about three times as much on a
/// whole-contract scan, since every allocation of one bundle gets the same
/// answer.
const VISIBLE_ASSIGNMENT: &str = " AND (a.bundle_id IS NULL OR a.bundle_id IN (SELECT \
                                  bw.bundle_id FROM bundle_witness bw JOIN witness_ord w ON \
                                  w.txid = bw.txid WHERE w.status <> 3)) AND NOT EXISTS (SELECT 1 \
                                  FROM invalid_op i WHERE i.opid = a.opid)";

/// The same restriction over `global_state g`, which has no operation to weigh
/// - global entries are dropped with their bundle, not with their op.
const VISIBLE_GLOBAL: &str = " AND (g.bundle_id IS NULL OR g.bundle_id IN (SELECT bw.bundle_id \
                              FROM bundle_witness bw JOIN witness_ord w ON w.txid = bw.txid WHERE \
                              w.status <> 3))";

/// The restriction [`Visibility::Valid`] adds to the witness branch of an
/// outpoint query: the witness the seal is resolved against must itself not be
/// archived. The bundle having some other valid witness is not enough - a seal
/// on a replaced transaction closes an outpoint which does not exist.
const VISIBLE_WITNESS_ASSIGNMENT: &str = " AND bw.txid IN (SELECT txid FROM witness_ord WHERE \
                                          status <> 3) AND NOT EXISTS (SELECT 1 FROM invalid_op i \
                                          WHERE i.opid = a.opid)";

/// The fragments above spell the archived status out, SQL having no way to
/// interpolate a constant into a literal.
const _: () = assert!(ORD_ARCHIVED == 3, "the visibility filters hardcode the archived status");

/// The restriction to add to an `assignment a` query when the caller asked for
/// visible rows only; nothing otherwise. No join: validity is a property of the
/// row's bundle, tested against a set, and the witness is not read from here at
/// all.
fn visibility_clause(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::All => "",
        Visibility::Valid => VISIBLE_ASSIGNMENT,
    }
}

/// [`visibility_clause`] for the witness branch of an outpoint query, see
/// [`VISIBLE_WITNESS_ASSIGNMENT`].
fn witness_visibility_clause(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::All => "",
        Visibility::Valid => VISIBLE_WITNESS_ASSIGNMENT,
    }
}

/// Splits a [`WitnessOrd`] into the `witness_ord` columns: status, and the
/// three position columns which are set together and only for a mined witness.
fn ord_columns(ord: WitnessOrd) -> (i64, Option<i64>, Option<i64>, Option<i64>) {
    match ord {
        WitnessOrd::Mined(pos) => (
            ORD_MINED,
            Some(i64::from(pos.height().get())),
            Some(pos.timestamp()),
            Some(i64::from(pos.layer1() as u8)),
        ),
        WitnessOrd::Tentative => (ORD_TENTATIVE, None, None, None),
        WitnessOrd::Ignored => (ORD_IGNORED, None, None, None),
        WitnessOrd::Archived => (ORD_ARCHIVED, None, None, None),
    }
}

/// Reassembles a [`WitnessOrd`] from the four columns [`ord_columns`] wrote,
/// starting at `first`.
///
/// Every way the columns can fail to describe a [`WitnessOrd`] is an error
/// rather than a silently substituted default.
fn ord_from_row(row: &rusqlite::Row<'_>, first: usize) -> Result<WitnessOrd, SqliteError> {
    let status: i64 = row.get(first)?;
    let mined = |what: &str, v: Option<i64>| {
        v.ok_or_else(|| SqliteError::Integrity(format!("mined WitnessOrd without a {what}")))
    };
    match status {
        ORD_MINED => {
            let height = mined("height", row.get(first + 1)?)?;
            let timestamp = mined("timestamp", row.get(first + 2)?)?;
            let layer1 = mined("layer1", row.get(first + 3)?)?;
            let height = u32::try_from(height)
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or_else(|| SqliteError::Integrity(format!("WitnessOrd height {height}")))?;
            let layer1 = match layer1 {
                0 => Layer1::Bitcoin,
                1 => Layer1::Liquid,
                other => {
                    return Err(SqliteError::Integrity(format!("WitnessOrd layer1 {other}")));
                }
            };
            // rejects a timestamp older than the layer's genesis, the one
            // invariant WitnessPos enforces on construction
            WitnessPos::with(layer1, height, timestamp)
                .map(WitnessOrd::Mined)
                .ok_or_else(|| SqliteError::Integrity(format!("WitnessOrd timestamp {timestamp}")))
        }
        ORD_TENTATIVE => Ok(WitnessOrd::Tentative),
        ORD_IGNORED => Ok(WitnessOrd::Ignored),
        ORD_ARCHIVED => Ok(WitnessOrd::Archived),
        other => Err(SqliteError::Integrity(format!("WitnessOrd status {other}"))),
    }
}

/// Single SQLite-backed [`RgbStore`].
///
/// Deliberately not `Clone`: the transaction belongs to the connection, so a
/// second handle to the same one would be a second owner of the same
/// transaction. One [`Stock`](crate::persistence::Stock) owns one store, and
/// concurrency comes from opening another database handle, not from sharing
/// this one.
#[derive(Debug)]
pub struct SqliteStore {
    db: SharedDb,
}

impl SqliteStore {
    pub(super) fn new(db: SharedDb) -> Self { Self { db } }
}

/// `'F' | 'S' | 'R'` marker stored in the `assignment.state_type` column: the
/// initial of each state family, so that none of them can be read as another.
fn kind_str(kind: AllocKind) -> &'static str {
    match kind {
        AllocKind::Fungible => "F",
        AllocKind::Structured => "S",
        AllocKind::Declarative => "R",
    }
}

/// Inverse of [`kind_str`]; `None` for an unrecognized marker.
fn kind_from_str(s: &str) -> Option<AllocKind> {
    match s {
        "F" => Some(AllocKind::Fungible),
        "S" => Some(AllocKind::Structured),
        "R" => Some(AllocKind::Declarative),
        _ => None,
    }
}

/// Builds `?first,...,?first+count-1`, the placeholder list for `count`
/// consecutive parameters bound from `first` on.
///
/// Indices are 1-based, matching rusqlite's `?N` numbering, so `first` is the
/// position of the first of these parameters in the whole statement: pass `1`
/// when they lead it, or a higher index when earlier ones are already bound.
fn placeholder_list(first: usize, count: usize) -> String {
    (first..first + count)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Builds `(?first,?first+1),...`, the [`placeholder_list`] grouped two at a
/// time into the parenthesized rows an `IN (VALUES ...)` clause expects.
///
/// `first` follows the same 1-based convention as [`placeholder_list`].
fn placeholder_pair_list(first: usize, count: usize) -> String {
    (0..count)
        .map(|i| format!("({})", placeholder_list(first + i * 2, 2)))
        .collect::<Vec<_>>()
        .join(",")
}

impl RgbStore for SqliteStore {
    type Error = SqliteError;

    // ----- transaction control ------------------------------------------------

    fn begin(&self, mode: TxMode) -> Result<TxBegin, Self::Error> { lock(&self.db)?.begin(mode) }
    fn commit(&self) -> Result<(), Self::Error> { lock(&self.db)?.commit() }
    fn rollback(&self) {
        // a poisoned mutex is recovered from rather than skipped: whatever
        // panicked while holding it may have left a transaction open, and
        // closing that is the one useful thing left to do with the connection
        self.db.lock().unwrap_or_else(|e| e.into_inner()).rollback();
    }

    // ----- schema definitions --------------------------------------------------

    fn schema(&self, schema_id: SchemaId) -> Result<Option<Schema>, Self::Error> {
        lock(&self.db)?
            .blob("SELECT schema_blob FROM schema WHERE schema_id = ?1", &enc(&schema_id)?)?
            .map(|blob| dec_keyed(&blob, "schema", schema_id, Schema::schema_id))
            .transpose()
    }

    fn put_schema(&mut self, schema: &Schema) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO schema (schema_id, schema_blob) VALUES (?1, ?2) ON CONFLICT (schema_id) \
             DO NOTHING",
            (enc(&schema.schema_id())?, enc(schema)?),
        )?;
        Ok(())
    }

    fn schemata(&self) -> impl Iterator<Item = Result<Schema, Self::Error>> + '_ {
        load_all(
            &self.db,
            // ordering here has a negligible cost as it's the PK (automatically indexed)
            "SELECT schema_id, schema_blob FROM schema ORDER BY schema_id",
            "schema",
            Schema::schema_id,
        )
        .into_iter()
    }

    // ----- type libraries / AluVM libraries -----------------------------------

    fn type_libs(&self, schema_id: SchemaId) -> Result<BTreeMap<TypeLibId, TypeLib>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached(
            "SELECT l.type_lib_id, l.type_lib_blob FROM type_lib l
             JOIN schema_type_lib s ON s.type_lib_id = l.type_lib_id
             WHERE s.schema_id = ?1",
        )?;
        let mut rows = stmt.query([enc(&schema_id)?])?;
        let mut libs = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let type_lib_id = dec::<TypeLibId>(&row.get::<_, Vec<u8>>(0)?)?;
            let blob: Vec<u8> = row.get(1)?;
            libs.insert(type_lib_id, dec_keyed(&blob, "type library", type_lib_id, TypeLib::id)?);
        }
        Ok(libs)
    }

    fn put_type_lib(&mut self, schema_id: SchemaId, type_lib: &TypeLib) -> Result<(), Self::Error> {
        let type_lib_id = enc(&type_lib.id())?;
        let db = lock(&self.db)?;
        db.conn.execute(
            "INSERT INTO type_lib (type_lib_id, type_lib_blob) VALUES (?1, ?2) ON CONFLICT \
             (type_lib_id) DO NOTHING",
            (&type_lib_id, enc(type_lib)?),
        )?;
        db.conn.execute(
            "INSERT INTO schema_type_lib (schema_id, type_lib_id) VALUES (?1, ?2) ON CONFLICT \
             (schema_id, type_lib_id) DO NOTHING",
            (enc(&schema_id)?, &type_lib_id),
        )?;
        Ok(())
    }

    fn aluvm_lib(&self, aluvm_lib_id: LibId) -> Result<Option<Lib>, Self::Error> {
        lock(&self.db)?
            .blob(
                "SELECT aluvm_lib_blob FROM aluvm_lib WHERE aluvm_lib_id = ?1",
                &enc(&aluvm_lib_id)?,
            )?
            .map(|blob| dec_keyed(&blob, "AluVM library", aluvm_lib_id, Lib::id))
            .transpose()
    }

    fn put_aluvm_lib(&mut self, aluvm_lib: &Lib) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO aluvm_lib (aluvm_lib_id, aluvm_lib_blob) VALUES (?1, ?2) ON CONFLICT \
             (aluvm_lib_id) DO NOTHING",
            (enc(&aluvm_lib.id())?, enc(aluvm_lib)?),
        )?;
        Ok(())
    }

    // ----- contracts (genesis) ------------------------------------------------

    fn genesis(&self, contract_id: ContractId) -> Result<Option<Genesis>, Self::Error> {
        lock(&self.db)?
            .blob("SELECT genesis_blob FROM genesis WHERE contract_id = ?1", &enc(&contract_id)?)?
            .map(|blob| dec_keyed(&blob, "genesis", contract_id, Genesis::contract_id))
            .transpose()
    }

    fn put_genesis(&mut self, genesis: &Genesis) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO genesis (contract_id, schema_id, genesis_blob) VALUES (?1, ?2, ?3) ON \
             CONFLICT(contract_id) DO UPDATE SET schema_id = excluded.schema_id, genesis_blob = \
             excluded.genesis_blob",
            (enc(&genesis.contract_id())?, enc(&genesis.schema_id)?, enc(genesis)?),
        )?;
        Ok(())
    }

    fn geneses(&self) -> impl Iterator<Item = Result<Genesis, Self::Error>> + '_ {
        load_all(
            &self.db,
            // ordering here has a negligible cost as it's the PK (automatically indexed)
            "SELECT contract_id, genesis_blob FROM genesis ORDER BY contract_id",
            "genesis",
            Genesis::contract_id,
        )
        .into_iter()
    }

    fn contract_schema(&self, contract_id: ContractId) -> Result<Option<Schema>, Self::Error> {
        // Single round-trip: join the contract's genesis to its schema. The
        // schema id comes back with it so the blob can be checked against the
        // key it is filed under, as the keyed lookups do
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached(
            "SELECT s.schema_id, s.schema_blob FROM schema s JOIN genesis g ON s.schema_id = \
             g.schema_id WHERE g.contract_id = ?1",
        )?;
        let row = stmt.query_row([enc(&contract_id)?], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        });
        match row {
            Ok((key, blob)) => {
                dec_keyed(&blob, "schema", dec::<SchemaId>(&key)?, Schema::schema_id).map(Some)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ----- bundles / witnesses / secret seals ---------------------------------

    fn bundle(&self, bundle_id: BundleId) -> Result<Option<TransitionBundle>, Self::Error> {
        lock(&self.db)?
            .blob("SELECT bundle_blob FROM bundle WHERE bundle_id = ?1", &enc(&bundle_id)?)?
            .map(|blob| dec_keyed(&blob, "bundle", bundle_id, TransitionBundle::bundle_id))
            .transpose()
    }

    fn put_bundle(&mut self, bundle: &TransitionBundle) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO bundle (bundle_id, bundle_blob) VALUES (?1, ?2) ON CONFLICT(bundle_id) \
             DO UPDATE SET bundle_blob = excluded.bundle_blob",
            (enc(&bundle.bundle_id())?, enc(bundle)?),
        )?;
        Ok(())
    }

    fn witness(&self, txid: Txid) -> Result<Option<SealWitness>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached(
            "SELECT tx_blob, mpc_merkle_block_blob, dbc_proof_blob, spv_proof_blob FROM witness \
             WHERE txid = ?1",
        )?;
        let row = stmt.query_row([enc(&txid)?], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        });
        let (tx, mpc_merkle_block, dbc_proof, spv_proof) = match row {
            Ok(parts) => parts,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some(SealWitness {
            // the key is the TX's own id, so a mismatch means this row is not
            // the witness it is filed under
            tx: dec_keyed(&tx, "witness", txid, Tx::compute_txid)?,
            mpc_merkle_block: dec(&mpc_merkle_block)?,
            dbc_proof: dec::<DbcProof>(&dbc_proof)?,
            spv_proof: spv_proof.map(|b| dec(&b)).transpose()?,
        }))
    }

    fn put_witness(&mut self, witness: &SealWitness) -> Result<(), Self::Error> {
        let spv_proof: Option<Vec<u8>> = witness.spv_proof.as_ref().map(enc).transpose()?;
        lock(&self.db)?.conn.execute(
            "INSERT INTO witness (txid, tx_blob, mpc_merkle_block_blob, dbc_proof_blob, \
             spv_proof_blob) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(txid) DO UPDATE SET tx_blob \
             = excluded.tx_blob, mpc_merkle_block_blob = excluded.mpc_merkle_block_blob, \
             dbc_proof_blob = excluded.dbc_proof_blob, spv_proof_blob = excluded.spv_proof_blob",
            rusqlite::params![
                enc(&witness.witness_id())?,
                enc(&witness.tx)?,
                enc(&witness.mpc_merkle_block)?,
                enc(&witness.dbc_proof)?,
                spv_proof,
            ],
        )?;
        Ok(())
    }

    fn witness_tx(&self, txid: Txid) -> Result<Option<Tx>, Self::Error> {
        lock(&self.db)?
            .blob("SELECT tx_blob FROM witness WHERE txid = ?1", &enc(&txid)?)?
            .map(|blob| dec_keyed(&blob, "witness", txid, Tx::compute_txid))
            .transpose()
    }

    fn witness_spv_proof(&self, txid: Txid) -> Result<Option<SpvProof>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT spv_proof_blob FROM witness WHERE txid = ?1")?;
        match stmt.query_row([enc(&txid)?], |row| row.get::<_, Option<Vec<u8>>>(0)) {
            Ok(Some(blob)) => dec(&blob).map(Some),
            Ok(None) | Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set_witness_spv_proof(
        &mut self,
        txid: Txid,
        spv_proof: Option<&SpvProof>,
    ) -> Result<bool, Self::Error> {
        let spv_proof: Option<Vec<u8>> = spv_proof.map(enc).transpose()?;
        // `IS NOT` rather than `<>`, so that NULL compares as a value and the
        // row is rewritten only when the proof actually changes
        let updated = lock(&self.db)?.conn.execute(
            "UPDATE witness SET spv_proof_blob = ?2 WHERE txid = ?1 AND spv_proof_blob IS NOT ?2",
            rusqlite::params![enc(&txid)?, spv_proof],
        )?;
        Ok(updated > 0)
    }

    fn seal_of_secret(&self, secret_seal: SecretSeal) -> Result<Option<GraphSeal>, Self::Error> {
        lock(&self.db)?
            .blob(
                "SELECT graph_seal_blob FROM secret_seal WHERE secret_seal = ?1",
                &enc(&secret_seal)?,
            )?
            // the key is the seal's own concealment, so a row filed under the
            // wrong one would reveal a seal for a secret it does not open
            .map(|blob| dec_keyed(&blob, "secret seal", secret_seal, GraphSeal::conceal))
            .transpose()
    }

    fn put_secret_seal(
        &mut self,
        graph_seal: &GraphSeal,
        secret_seal: SecretSeal,
    ) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO secret_seal (secret_seal, graph_seal_blob) VALUES (?1, ?2) ON CONFLICT \
             (secret_seal) DO NOTHING",
            (enc(&secret_seal)?, enc(graph_seal)?),
        )?;
        Ok(())
    }

    // ----- global state -------------------------------------------------------

    fn globals(
        &self,
        contract_id: ContractId,
        type_id: GlobalStateType,
        visibility: Visibility,
    ) -> Result<Vec<GlobalStateRow>, Self::Error> {
        // No join to witness_ord: which witness a row is reported under is the
        // caller's to resolve through `witnesses_of_bundles`, and validity is
        // decided against the bundle's witness set by `VISIBLE_GLOBAL` alone.
        let filter = match visibility {
            Visibility::All => "",
            Visibility::Valid => VISIBLE_GLOBAL,
        };
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached(&format!(
            "SELECT g.opid, g.out_index, g.nonce, g.bundle_id, g.transition_type, g.value_blob \
             FROM global_state g WHERE g.contract_id = ?1 AND g.type_id = ?2{filter}"
        ))?;
        let mut rows =
            stmt.query(rusqlite::params![enc(&contract_id)?, i64::from(type_id.into_inner())])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(decode_global_row(row)?);
        }
        Ok(out)
    }

    fn put_global(&mut self, global_state: GlobalStateWrite<'_>) -> Result<(), Self::Error> {
        let bundle_id = global_state.bundle_id.as_ref().map(enc).transpose()?;
        let transition_type = global_state
            .transition_type
            .map(|ty| i64::from(ty.into_inner()));
        lock(&self.db)?.conn.execute(
            "INSERT INTO global_state (contract_id, type_id, opid, out_index, nonce, bundle_id, \
             transition_type, value_blob) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT \
             (contract_id, type_id, opid, out_index) DO NOTHING",
            rusqlite::params![
                enc(&global_state.contract_id)?,
                i64::from(global_state.type_id.into_inner()),
                enc(&global_state.opid)?,
                i64::from(global_state.index),
                // u64 bit-cast into the signed column; nothing compares it in SQL
                global_state.nonce as i64,
                bundle_id,
                transition_type,
                enc(global_state.value)?,
            ],
        )?;
        Ok(())
    }

    // ----- allocations (owned state) ------------------------------------------

    fn allocations(
        &self,
        contract_id: ContractId,
        filter: AllocationFilter<'_>,
    ) -> Result<Vec<AllocationRow>, Self::Error> {
        let vis = visibility_clause(filter.visibility);
        let wvis = witness_visibility_clause(filter.visibility);
        // the narrowings the caller asked for, bound as the leading parameters;
        // the outpoint pairs, when there are any, are bound after them
        let mut lead: Vec<Value> = vec![Value::Blob(enc(&contract_id)?)];
        let mut narrow = String::from("a.contract_id = ?1");
        if let Some(kind) = filter.kind {
            lead.push(Value::Text(kind_str(kind).into()));
            narrow.push_str(&format!(" AND a.state_type = ?{}", lead.len()));
        }
        if let Some(ty) = filter.type_id {
            lead.push(Value::Integer(i64::from(ty.into_inner())));
            narrow.push_str(&format!(" AND a.type_id = ?{}", lead.len()));
        }

        let db = lock(&self.db)?;
        let mut out = Vec::new();
        let Some(outpoints) = filter.outpoints else {
            let sql = format!("{ALLOC_COLS} FROM assignment a WHERE {narrow}{vis}");
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(lead.iter()))?;
            while let Some(row) = rows.next()? {
                out.push(decode_alloc_row(row)?);
            }
            return Ok(out);
        };
        if outpoints.is_empty() {
            return Ok(out);
        }
        let outpoints: Vec<&Outpoint> = outpoints.iter().collect();
        for chunk in outpoints.chunks(QUERY_CHUNK) {
            let mut params = lead.clone();
            params.reserve(chunk.len() * 2);
            for o in chunk {
                params.push(Value::Blob(enc(&o.txid)?));
                params.push(Value::Integer(i64::from(o.vout)));
            }
            let sql = format!(
                "WITH q(txid, vout) AS (VALUES {}) {}",
                placeholder_pair_list(lead.len() + 1, chunk.len()),
                alloc_at_outpoints_sql(
                    ALLOC_COLS,
                    WITNESS_ALLOC_COLS,
                    &format!("{narrow} AND"),
                    vis,
                    wvis
                )
            );
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            while let Some(row) = rows.next()? {
                out.push(decode_alloc_row(row)?);
            }
        }
        Ok(out)
    }

    fn all_allocations_at_outpoints(
        &self,
        outpoints: &BTreeSet<Outpoint>,
        visibility: Visibility,
    ) -> Result<Vec<(ContractId, AllocationRow)>, Self::Error> {
        let mut out = Vec::new();
        if outpoints.is_empty() {
            return Ok(out);
        }
        let vis = visibility_clause(visibility);
        let wvis = witness_visibility_clause(visibility);
        let outpoints: Vec<&Outpoint> = outpoints.iter().collect();
        let db = lock(&self.db)?;
        for chunk in outpoints.chunks(QUERY_CHUNK) {
            let mut params: Vec<Value> = Vec::with_capacity(chunk.len() * 2);
            for o in chunk {
                params.push(Value::Blob(enc(&o.txid)?));
                params.push(Value::Integer(i64::from(o.vout)));
            }
            // No ORDER BY: the caller groups the rows by contract, so row order
            // is irrelevant
            let sql = format!(
                "WITH q(txid, vout) AS (VALUES {}) {}",
                placeholder_pair_list(1, chunk.len()),
                alloc_at_outpoints_sql(
                    &format!("{ALLOC_COLS}, a.contract_id"),
                    &format!("{WITNESS_ALLOC_COLS}, a.contract_id"),
                    "",
                    vis,
                    wvis
                )
            );
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            while let Some(row) = rows.next()? {
                let contract_id = dec::<ContractId>(&row.get::<_, Vec<u8>>(8)?)?;
                out.push((contract_id, decode_alloc_row(row)?));
            }
        }
        Ok(out)
    }

    /// Ignores a second write of the same assignment: the seal is stored as
    /// defined, so re-consuming a bundle under another witness writes the same
    /// row again. That witness is picked up through `bundle_witness` instead,
    /// without the row having to change.
    fn put_allocation(&mut self, allocation: AllocationWrite<'_>) -> Result<(), Self::Error> {
        let bundle_id = allocation.bundle_id.as_ref().map(enc).transpose()?;
        lock(&self.db)?.conn.execute(
            "INSERT INTO assignment (contract_id, state_type, type_id, opid, output_no, \
             seal_txid, seal_vout, bundle_id, value_blob) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, \
             ?9) ON CONFLICT (contract_id, opid, type_id, output_no) DO NOTHING",
            rusqlite::params![
                enc(&allocation.contract_id)?,
                kind_str(allocation.kind),
                i64::from(allocation.opout.ty.into_inner()),
                enc(&allocation.opout.op)?,
                i64::from(allocation.opout.no),
                allocation.seal.txid.as_ref().map(enc).transpose()?,
                i64::from(allocation.seal.vout.to_u32()),
                bundle_id,
                allocation.value,
            ],
        )?;
        Ok(())
    }

    // ----- WitnessOrd / invalid ops -------------------------------------------

    /// Asking for one witness is asking for a set of one: [`Self::witness_ords`]
    /// is the single implementation, so the two cannot drift apart.
    fn witness_ord(&self, txid: Txid) -> Result<Option<WitnessOrd>, Self::Error> {
        Ok(self.witness_ords(&BTreeSet::from([txid]))?.remove(&txid))
    }

    fn witness_ords(
        &self,
        txids: &BTreeSet<Txid>,
    ) -> Result<BTreeMap<Txid, WitnessOrd>, Self::Error> {
        let mut out = BTreeMap::new();
        if txids.is_empty() {
            return Ok(out);
        }
        let txids: Vec<&Txid> = txids.iter().collect();
        let db = lock(&self.db)?;
        for chunk in txids.chunks(QUERY_CHUNK) {
            let mut params: Vec<Value> = Vec::with_capacity(chunk.len());
            for txid in chunk {
                params.push(Value::Blob(enc(*txid)?));
            }
            let sql = format!(
                "SELECT txid, status, height, timestamp, layer1 FROM witness_ord WHERE txid IN \
                 ({})",
                placeholder_list(1, chunk.len())
            );
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            while let Some(row) = rows.next()? {
                let txid = dec::<Txid>(&row.get::<_, Vec<u8>>(0)?)?;
                out.insert(txid, ord_from_row(row, 1)?);
            }
        }
        Ok(out)
    }

    fn witness_ords_to_refresh(
        &self,
        min_height: NonZeroU32,
    ) -> Result<BTreeSet<Txid>, Self::Error> {
        let db = lock(&self.db)?;
        // Lead on `status` for both arms of the OR so the database can answer
        // from the (status, height) index instead of having to check every row
        // in the table.
        let mut stmt = db.conn.prepare_cached(&format!(
            "SELECT txid FROM witness_ord WHERE (status = {ORD_MINED} AND height >= ?1) OR status \
             IN ({ORD_TENTATIVE}, {ORD_ARCHIVED})"
        ))?;
        let mut rows = stmt.query([i64::from(min_height.get())])?;
        let mut out = BTreeSet::new();
        while let Some(row) = rows.next()? {
            out.insert(dec::<Txid>(&row.get::<_, Vec<u8>>(0)?)?);
        }
        Ok(out)
    }

    fn all_witness_ords(&self) -> Result<BTreeMap<Txid, WitnessOrd>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT txid, status, height, timestamp, layer1 FROM witness_ord")?;
        let mut rows = stmt.query([])?;
        let mut out = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let txid = dec::<Txid>(&row.get::<_, Vec<u8>>(0)?)?;
            out.insert(txid, ord_from_row(row, 1)?);
        }
        Ok(out)
    }

    fn put_witness_ord(&mut self, txid: Txid, ord: WitnessOrd) -> Result<(), Self::Error> {
        let (status, height, timestamp, layer1) = ord_columns(ord);
        lock(&self.db)?.conn.execute(
            "INSERT OR REPLACE INTO witness_ord (txid, status, height, timestamp, layer1) VALUES \
             (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![enc(&txid)?, status, height, timestamp, layer1],
        )?;
        Ok(())
    }

    fn all_invalid_ops(&self) -> Result<BTreeSet<OpId>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached("SELECT opid FROM invalid_op")?;
        let mut rows = stmt.query([])?;
        let mut out = BTreeSet::new();
        while let Some(row) = rows.next()? {
            out.insert(dec::<OpId>(&row.get::<_, Vec<u8>>(0)?)?);
        }
        Ok(out)
    }

    fn any_op_invalid(&self, opids: &BTreeSet<OpId>) -> Result<bool, Self::Error> {
        if opids.is_empty() {
            return Ok(false);
        }
        let opids: Vec<&OpId> = opids.iter().collect();
        let db = lock(&self.db)?;
        for chunk in opids.chunks(QUERY_CHUNK) {
            let mut params: Vec<Value> = Vec::with_capacity(chunk.len());
            for opid in chunk {
                params.push(Value::Blob(enc(*opid)?));
            }
            // LIMIT 1: the answer is whether one exists, not how many do
            let sql = format!(
                "SELECT 1 FROM invalid_op WHERE opid IN ({}) LIMIT 1",
                placeholder_list(1, chunk.len())
            );
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            if rows.next()?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn set_op_validity(&mut self, opid: OpId, valid: bool) -> Result<(), Self::Error> {
        let key = enc(&opid)?;
        let db = lock(&self.db)?;
        if valid {
            db.conn
                .execute("DELETE FROM invalid_op WHERE opid = ?1", (key,))?;
        } else {
            db.conn.execute(
                "INSERT INTO invalid_op (opid) VALUES (?1) ON CONFLICT (opid) DO NOTHING",
                (key,),
            )?;
        }
        Ok(())
    }

    // ----- index: contract / bundle / op graph --------------------------------

    fn contract_registered(&self, contract_id: ContractId) -> Result<bool, Self::Error> {
        lock(&self.db)?.exists("SELECT 1 FROM genesis WHERE contract_id = ?1", &enc(&contract_id)?)
    }

    fn bundle_contract(&self, bundle_id: BundleId) -> Result<Option<ContractId>, Self::Error> {
        lock(&self.db)?
            .blob(
                "SELECT contract_id FROM bundle_contract WHERE bundle_id = ?1",
                &enc(&bundle_id)?,
            )?
            .map(|blob| dec(&blob))
            .transpose()
    }

    fn put_bundle_contract(
        &mut self,
        bundle_id: BundleId,
        contract_id: ContractId,
    ) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT OR REPLACE INTO bundle_contract (bundle_id, contract_id) VALUES (?1, ?2)",
            (enc(&bundle_id)?, enc(&contract_id)?),
        )?;
        Ok(())
    }

    fn bundle_witnesses(&self, bundle_id: BundleId) -> Result<BTreeSet<Txid>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT txid FROM bundle_witness WHERE bundle_id = ?1")?;
        let mut rows = stmt.query([enc(&bundle_id)?])?;
        let mut out = BTreeSet::new();
        while let Some(row) = rows.next()? {
            out.insert(dec::<Txid>(&row.get::<_, Vec<u8>>(0)?)?);
        }
        Ok(out)
    }

    fn witnesses_of_bundles(
        &self,
        bundle_ids: &BTreeSet<BundleId>,
    ) -> Result<BTreeMap<BundleId, BTreeSet<Txid>>, Self::Error> {
        let mut out: BTreeMap<BundleId, BTreeSet<Txid>> = BTreeMap::new();
        if bundle_ids.is_empty() {
            return Ok(out);
        }
        let bundle_ids: Vec<&BundleId> = bundle_ids.iter().collect();
        let db = lock(&self.db)?;
        for chunk in bundle_ids.chunks(QUERY_CHUNK) {
            let mut params: Vec<Value> = Vec::with_capacity(chunk.len());
            for bundle_id in chunk {
                params.push(Value::Blob(enc(*bundle_id)?));
            }
            let sql = format!(
                "SELECT bundle_id, txid FROM bundle_witness WHERE bundle_id IN ({})",
                placeholder_list(1, chunk.len())
            );
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            while let Some(row) = rows.next()? {
                let bundle_id = dec::<BundleId>(&row.get::<_, Vec<u8>>(0)?)?;
                let txid = dec::<Txid>(&row.get::<_, Vec<u8>>(1)?)?;
                out.entry(bundle_id).or_default().insert(txid);
            }
        }
        Ok(out)
    }

    fn bundles_of_witness(&self, txid: Txid) -> Result<BTreeSet<BundleId>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT bundle_id FROM bundle_witness WHERE txid = ?1")?;
        let mut rows = stmt.query([enc(&txid)?])?;
        let mut out = BTreeSet::new();
        while let Some(row) = rows.next()? {
            out.insert(dec::<BundleId>(&row.get::<_, Vec<u8>>(0)?)?);
        }
        Ok(out)
    }

    fn put_bundle_witness(&mut self, bundle_id: BundleId, txid: Txid) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO bundle_witness (bundle_id, txid) VALUES (?1, ?2) ON CONFLICT (bundle_id, \
             txid) DO NOTHING",
            (enc(&bundle_id)?, enc(&txid)?),
        )?;
        Ok(())
    }

    fn bundle_of_op(&self, opid: OpId) -> Result<Option<BundleId>, Self::Error> {
        lock(&self.db)?
            .blob("SELECT bundle_id FROM op_bundle WHERE opid = ?1", &enc(&opid)?)?
            .map(|blob| dec(&blob))
            .transpose()
    }

    fn ops_in_bundle(&self, bundle_id: BundleId) -> Result<BTreeSet<OpId>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT opid FROM op_bundle WHERE bundle_id = ?1")?;
        let mut rows = stmt.query([enc(&bundle_id)?])?;
        let mut out = BTreeSet::new();
        while let Some(row) = rows.next()? {
            out.insert(dec::<OpId>(&row.get::<_, Vec<u8>>(0)?)?);
        }
        Ok(out)
    }

    fn put_op_bundle(&mut self, opid: OpId, bundle_id: BundleId) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO op_bundle (opid, bundle_id) VALUES (?1, ?2) ON CONFLICT (opid) DO NOTHING",
            (enc(&opid)?, enc(&bundle_id)?),
        )?;
        Ok(())
    }

    fn child_bundles_of_op(&self, opid: OpId) -> Result<BTreeSet<BundleId>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            // DISTINCT: without it, a child spending several outputs of the
            // parent would be returned multiple times (one row per spent
            // opout); with it, once per bundle. The return type is a set, so
            // this just avoids wasting query time.
            .prepare_cached("SELECT DISTINCT child_bundle_id FROM op_input WHERE opid = ?1")?;
        let mut rows = stmt.query([enc(&opid)?])?;
        let mut out = BTreeSet::new();
        while let Some(row) = rows.next()? {
            out.insert(dec::<BundleId>(&row.get::<_, Vec<u8>>(0)?)?);
        }
        Ok(out)
    }

    fn child_ops_of_op(&self, opid: OpId) -> Result<BTreeSet<(OpId, BundleId)>, Self::Error> {
        let db = lock(&self.db)?;
        // DISTINCT: a child spending several outputs of the parent is one edge
        // per spent opout in the table, and one child here. The return type is
        // a set, so this just avoids wasting query time.
        let mut stmt = db.conn.prepare_cached(
            "SELECT DISTINCT child_opid, child_bundle_id FROM op_input WHERE opid = ?1",
        )?;
        let mut rows = stmt.query([enc(&opid)?])?;
        let mut out = BTreeSet::new();
        while let Some(row) = rows.next()? {
            let child_opid = dec::<OpId>(&row.get::<_, Vec<u8>>(0)?)?;
            let child_bundle_id = dec::<BundleId>(&row.get::<_, Vec<u8>>(1)?)?;
            out.insert((child_opid, child_bundle_id));
        }
        Ok(out)
    }

    fn input_opouts_for_op(&self, opid: OpId) -> Result<BTreeSet<Opout>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached(
            "SELECT opid, type_id, output_no FROM op_input WHERE child_opid = ?1",
        )?;
        let mut rows = stmt.query([enc(&opid)?])?;
        let mut out = BTreeSet::new();
        while let Some(row) = rows.next()? {
            let parent_opid = dec::<OpId>(&row.get::<_, Vec<u8>>(0)?)?;
            let ty: i64 = row.get(1)?;
            let no: i64 = row.get(2)?;
            out.insert(Opout::new(parent_opid, AssignmentType::with(ty as u16), no as u16));
        }
        Ok(out)
    }

    fn put_op_input(
        &mut self,
        spent_opout: Opout,
        child_opid: OpId,
        child_bundle_id: BundleId,
    ) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO op_input (opid, type_id, output_no, child_opid, child_bundle_id) VALUES \
             (?1, ?2, ?3, ?4, ?5) ON CONFLICT (opid, type_id, output_no, child_opid) DO NOTHING",
            (
                enc(&spent_opout.op)?,
                i64::from(spent_opout.ty.into_inner()),
                i64::from(spent_opout.no),
                enc(&child_opid)?,
                enc(&child_bundle_id)?,
            ),
        )?;
        Ok(())
    }

    // ----- index: outpoint->opout and secret-seal->opout ------------------------

    fn opouts_at(
        &self,
        contract_id: ContractId,
        outpoints: &BTreeSet<Outpoint>,
    ) -> Result<BTreeMap<Outpoint, BTreeSet<Opout>>, Self::Error> {
        let mut out = BTreeMap::<Outpoint, BTreeSet<Opout>>::new();
        if outpoints.is_empty() {
            return Ok(out);
        }
        let cid = enc(&contract_id)?;
        let outpoints: Vec<&Outpoint> = outpoints.iter().collect();
        let db = lock(&self.db)?;
        for chunk in outpoints.chunks(QUERY_CHUNK) {
            let mut params: Vec<Value> = Vec::with_capacity(chunk.len() * 2 + 1);
            params.push(Value::Blob(cid.clone()));
            for o in chunk {
                params.push(Value::Blob(enc(&o.txid)?));
                params.push(Value::Integer(i64::from(o.vout)));
            }
            let sql = format!(
                "SELECT txid, vout, opout FROM outpoint_opout WHERE contract_id = ?1 AND (txid, \
                 vout) IN (VALUES {})",
                placeholder_pair_list(2, chunk.len())
            );
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            while let Some(row) = rows.next()? {
                let txid = dec::<Txid>(&row.get::<_, Vec<u8>>(0)?)?;
                let vout: i64 = row.get(1)?;
                let opout = dec::<Opout>(&row.get::<_, Vec<u8>>(2)?)?;
                out.entry(Outpoint::new(txid, vout as u32))
                    .or_default()
                    .insert(opout);
            }
        }
        Ok(out)
    }

    fn contracts_assigning(
        &self,
        outpoints: &BTreeSet<Outpoint>,
    ) -> Result<BTreeSet<ContractId>, Self::Error> {
        let mut out = BTreeSet::new();
        if outpoints.is_empty() {
            return Ok(out);
        }
        let outpoints: Vec<&Outpoint> = outpoints.iter().collect();
        let db = lock(&self.db)?;
        for chunk in outpoints.chunks(QUERY_CHUNK) {
            let mut params: Vec<Value> = Vec::with_capacity(chunk.len() * 2);
            for o in chunk {
                params.push(Value::Blob(enc(&o.txid)?));
                params.push(Value::Integer(i64::from(o.vout)));
            }
            let sql = format!(
                // DISTINCT: without it, several assignments of the same
                // contract would return that contract more than once. The
                // return type is a set, so this just avoids wasting query time.
                "SELECT DISTINCT contract_id FROM outpoint_opout WHERE (txid, vout) IN (VALUES {})",
                placeholder_pair_list(1, chunk.len())
            );
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            while let Some(row) = rows.next()? {
                out.insert(dec::<ContractId>(&row.get::<_, Vec<u8>>(0)?)?);
            }
        }
        Ok(out)
    }

    fn put_outpoint_opout(
        &mut self,
        contract_id: ContractId,
        outpoint: Outpoint,
        opout: Opout,
    ) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO outpoint_opout (contract_id, txid, vout, opout) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (contract_id, txid, vout, opout) DO NOTHING",
            (enc(&contract_id)?, enc(&outpoint.txid)?, i64::from(outpoint.vout), enc(&opout)?),
        )?;
        Ok(())
    }

    fn opouts_by_secrets(
        &self,
        contract_id: ContractId,
        secret_seals: &BTreeSet<SecretSeal>,
    ) -> Result<BTreeSet<Opout>, Self::Error> {
        let mut out = BTreeSet::new();
        if secret_seals.is_empty() {
            return Ok(out);
        }
        let cid = enc(&contract_id)?;
        let secret_seals: Vec<&SecretSeal> = secret_seals.iter().collect();
        let db = lock(&self.db)?;
        for chunk in secret_seals.chunks(QUERY_CHUNK) {
            let mut params: Vec<Value> = Vec::with_capacity(chunk.len() + 1);
            params.push(Value::Blob(cid.clone()));
            for secret_seal in chunk {
                params.push(Value::Blob(enc(*secret_seal)?));
            }
            let sql = format!(
                "SELECT opout FROM secret_seal_opout WHERE contract_id = ?1 AND secret_seal IN \
                 ({})",
                placeholder_list(2, chunk.len())
            );
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            while let Some(row) = rows.next()? {
                out.insert(dec::<Opout>(&row.get::<_, Vec<u8>>(0)?)?);
            }
        }
        Ok(out)
    }

    fn put_secret_opout(
        &mut self,
        contract_id: ContractId,
        secret_seal: SecretSeal,
        opout: Opout,
    ) -> Result<(), Self::Error> {
        lock(&self.db)?.conn.execute(
            "INSERT INTO secret_seal_opout (contract_id, secret_seal, opout) VALUES (?1, ?2, ?3) \
             ON CONFLICT (contract_id, secret_seal, opout) DO NOTHING",
            (enc(&contract_id)?, enc(&secret_seal)?, enc(&opout)?),
        )?;
        Ok(())
    }
}

/// Reassembles a `global_state` row, joined to its [`WitnessOrd`], into
/// `(GlobalOut, Option<WitnessOrd>, RevealedData)`.
///
/// `bundle_id` and `transition_type` are set together or not at all, as
/// guaranteed by the CHECK constraint, to construct the [`OpWitness`] enum.
fn decode_global_row(row: &rusqlite::Row<'_>) -> Result<GlobalStateRow, SqliteError> {
    let opid: Vec<u8> = row.get(0)?;
    let out_index: i64 = row.get(1)?;
    let nonce: i64 = row.get(2)?;
    let bundle_id: Option<Vec<u8>> = row.get(3)?;
    let transition_type: Option<i64> = row.get(4)?;
    let value_blob: Vec<u8> = row.get(5)?;

    let (bundle_id, transition_type) = match (bundle_id, transition_type) {
        (None, None) => (None, None),
        (Some(bundle_id), Some(ty)) => {
            (Some(dec::<BundleId>(&bundle_id)?), Some(TransitionType::with(ty as u16)))
        }
        _ => {
            return Err(SqliteError::Integrity(s!(
                "global state entry with only half of its bundle"
            )));
        }
    };
    Ok(GlobalStateRow {
        opid: dec::<OpId>(&opid)?,
        index: out_index as u16,
        nonce: nonce as u64,
        bundle_id,
        transition_type,
        value: dec::<RevealedData>(&value_blob)?,
    })
}

/// The `state_type` column at `idx`, as an [`AllocKind`]. The column is
/// constrained to 'F' / 'S' / 'R' by the table's CHECK, so an unknown value is
/// corruption rather than a row to pass over.
fn decode_kind(row: &rusqlite::Row<'_>, idx: usize) -> Result<AllocKind, SqliteError> {
    let state_type: String = row.get(idx)?;
    kind_from_str(&state_type).ok_or_else(|| {
        SqliteError::Integrity(format!("assignment with unknown state type {state_type}"))
    })
}

/// Decodes the [`ALLOC_COLS`] columns into an [`AllocationRow`].
fn decode_alloc_row(row: &rusqlite::Row<'_>) -> Result<AllocationRow, SqliteError> {
    let type_id: i64 = row.get(0)?;
    let opid: Vec<u8> = row.get(1)?;
    let output_no: i64 = row.get(2)?;
    let seal_txid: Option<Vec<u8>> = row.get(3)?;
    let seal_vout: i64 = row.get(4)?;
    let bundle_id: Option<Vec<u8>> = row.get(5)?;
    let value: Vec<u8> = row.get(6)?;
    let kind = decode_kind(row, 7)?;

    let opid = dec::<OpId>(&opid)?;
    let ty = AssignmentType::with(type_id as u16);
    let opout = Opout::new(opid, ty, output_no as u16);
    let seal = AllocSeal {
        txid: seal_txid.as_deref().map(dec::<Txid>).transpose()?,
        vout: Vout::from_u32(seal_vout as u32),
    };
    let bundle_id = bundle_id.as_deref().map(dec::<BundleId>).transpose()?;
    Ok(AllocationRow {
        kind,
        opout,
        seal,
        bundle_id,
        value,
    })
}
