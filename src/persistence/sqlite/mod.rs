// RGB ops library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 RGB-Tools developers. All rights reserved.
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

//! SQLite-backed [`RgbStore`](crate::persistence::RgbStore) implementation.
//!
//! The store owns one [`rusqlite::Connection`], so a Stock store transaction
//! maps onto exactly one SQL transaction over that connection.

mod schema;
mod store;

use std::fmt::Display;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, ErrorCode};
use strict_encoding::{DeserializeError, StrictDecode, StrictEncode};

pub use self::store::SqliteStore;
use crate::persistence::{codec, Stock, TxBegin, TxMode};

/// Stock persisting all of its data in a single SQLite database.
pub type SqliteStock = Stock<SqliteStore>;

impl SqliteStock {
    /// Opens (creating and migrating when needed) a stock at the given
    /// database file path.
    ///
    /// Each call is a connection of its own, owned by the stock it returns.
    /// Several may be open on one database file, in this process or across
    /// processes: readers run together and writers are serialized by SQLite's
    /// own write lock. See the concurrency notes in [`crate::persistence`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteError> {
        Self::with_connection(Connection::open(path)?)
    }

    /// Transient in-memory stock (mostly useful for testing).
    pub fn in_memory() -> Result<Self, SqliteError> {
        Self::with_connection(Connection::open_in_memory()?)
    }

    fn with_connection(conn: Connection) -> Result<Self, SqliteError> {
        schema::migrate(&conn)?;
        let db = Arc::new(Mutex::new(Db { conn }));
        Ok(Stock::with(SqliteStore::new(db)))
    }
}

/// Error type for the SQLite-backed store.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum SqliteError {
    /// the database is busy: another connection holds a transaction which this
    /// operation would have had to wait out. {0}
    ///
    /// Reported rather than retried: how long to wait, and whether the work is
    /// still worth doing, is the caller's to decide.
    Busy(String),

    /// SQLite storage error: {0}
    Storage(String),

    /// stored data is inconsistent: {0}
    ///
    /// A record decoded from a blob disagrees with the column it is keyed by.
    /// Distinct from [`SqliteError::Storage`] because the read itself succeeded:
    /// the database is reachable and the blob is well-formed, but the row is
    /// not the row it is filed under, so retrying will not help and the value
    /// must not be used.
    Integrity(String),
}

impl SqliteError {
    fn poisoned() -> Self { SqliteError::Storage(s!("database mutex is poisoned")) }
}

impl From<rusqlite::Error> for SqliteError {
    fn from(err: rusqlite::Error) -> Self {
        // contention is a distinct outcome, not a storage fault: the database is
        // intact and the same operation may well succeed once the other
        // connection is done
        match err.sqlite_error_code() {
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => {
                SqliteError::Busy(err.to_string())
            }
            _ => SqliteError::Storage(err.to_string()),
        }
    }
}

impl From<DeserializeError> for SqliteError {
    fn from(err: DeserializeError) -> Self {
        SqliteError::Storage(format!("cannot decode stored data: {err}"))
    }
}

/// Shared database handle wrapping the single SQLite connection.
#[derive(Debug)]
struct Db {
    conn: Connection,
}

type SharedDb = Arc<Mutex<Db>>;

fn lock(db: &SharedDb) -> Result<MutexGuard<'_, Db>, SqliteError> {
    db.lock().map_err(|_| SqliteError::poisoned())
}

// SQLite's own autocommit state is the single source of truth for whether a
// transaction is open (`is_autocommit()` is `true` when none is), so there is
// no separate flag to keep in sync. Deciding and acting on it happen under the
// single lock the caller took, so two threads cannot both conclude they opened
// the transaction.
impl Db {
    /// Opens the SQL transaction, reporting whether it opened one or found one
    /// already open.
    ///
    /// `IMMEDIATE` rather than the default deferred `BEGIN`: a stock
    /// transaction reads before it writes, and a deferred one takes the write
    /// lock only at that first write, where the upgrade can fail with
    /// `SQLITE_BUSY_SNAPSHOT` against a second connection. SQLite does not
    /// consult the busy handler for an upgrade, since waiting there could
    /// deadlock. Taking the lock upfront moves the contention to `begin`, where
    /// rusqlite's 5-second busy timeout does wait it out before
    /// [`SqliteError::Busy`].
    fn begin(&mut self, mode: TxMode) -> Result<TxBegin, SqliteError> {
        if !self.conn.is_autocommit() {
            return Ok(TxBegin::AlreadyOpen);
        }
        self.conn.execute_batch(match mode {
            // deferred: the shared lock is taken at the first read and held to
            // the end, which is all a read needs - and taking the write lock
            // instead would make two readers wait for each other
            TxMode::Read => "BEGIN DEFERRED",
            TxMode::Write => "BEGIN IMMEDIATE",
        })?;
        Ok(TxBegin::Opened)
    }

    /// Commits the open transaction, atomically covering every write in the
    /// unit of work; a no-op if none is open.
    fn commit(&mut self) -> Result<(), SqliteError> {
        if !self.conn.is_autocommit() {
            self.conn.execute_batch("COMMIT")?;
        }
        Ok(())
    }

    /// Rolls back the open transaction; a no-op if none is open.
    fn rollback(&mut self) {
        if !self.conn.is_autocommit() {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }

    /// Runs a single-blob-column keyed lookup, mapping the no-rows case to
    /// `None`.
    fn blob(&self, sql: &str, key: &[u8]) -> Result<Option<Vec<u8>>, SqliteError> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        match stmt.query_row([key], |row| row.get::<_, Vec<u8>>(0)) {
            Ok(blob) => Ok(Some(blob)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Checks whether a keyed row exists.
    fn exists(&self, sql: &str, key: &[u8]) -> Result<bool, SqliteError> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        stmt.exists([key]).map_err(SqliteError::from)
    }
}

/// Strict-encodes a value into a blob stored in the database.
fn enc(val: &impl StrictEncode) -> Result<Vec<u8>, SqliteError> {
    codec::encode(val).map_err(|e| SqliteError::Storage(format!("cannot serialize data: {e}")))
}

/// Strict-decodes a blob retrieved from the database, ensuring it is consumed
/// in full.
fn dec<T: StrictDecode>(blob: &[u8]) -> Result<T, SqliteError> {
    codec::decode(blob).map_err(SqliteError::from)
}

/// Strict-decodes a store record and checks that the key it was filed under is
/// the key the record itself derives.
///
/// A store record is addressed by an id computed from its own content - a
/// schema id, a contract id, a bundle id, a witness txid, a library id, a seal
/// concealment - so the id lives both in an indexed column and, implicitly, in
/// the blob. That is the one duplication the schema keeps, and recomputing the
/// id on read is what keeps the two from silently diverging: a mismatch means
/// the row is filed under the wrong key, and returning it would hand the caller
/// a record which is not the one it asked for. Cheap enough to always run -
/// deriving the id costs the same order as the decode which precedes it.
///
/// `what` names the record for the error message; `key_of` derives the id from
/// the decoded value.
fn dec_keyed<T, K>(
    blob: &[u8],
    what: &str,
    key: K,
    key_of: impl FnOnce(&T) -> K,
) -> Result<T, SqliteError>
where
    T: StrictDecode,
    K: Eq + Display,
{
    let val = dec::<T>(blob)?;
    let found = key_of(&val);
    if found != key {
        return Err(SqliteError::Integrity(format!(
            "{what} stored under {key} holds data for {found}"
        )));
    }
    Ok(val)
}

/// Runs a whole-table scan selecting a key column and a blob column, checking
/// every row against its key as [`dec_keyed`] does.
///
/// The scan is done eagerly, under one lock, so no borrow of the connection
/// ever escapes into the returned iterator. A failure - of the query itself, or
/// of decoding or checking any row - surfaces as the single item of the
/// returned vector: an inconsistent store is not something to report one row
/// into an iteration of it.
///
/// The closure acts as a `try` block, which is still unstable as of rust 1.97.
fn load_all<T, K>(
    db: &SharedDb,
    sql: &str,
    what: &str,
    key_of: impl Fn(&T) -> K,
) -> Vec<Result<T, SqliteError>>
where
    T: StrictDecode,
    K: StrictDecode + Eq + Display,
{
    let res = (|| {
        let db = lock(db)?;
        let mut stmt = db.conn.prepare_cached(sql)?;
        let mut rows = stmt.query([])?;
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            let key = dec::<K>(&row.get::<_, Vec<u8>>(0)?)?;
            let blob: Vec<u8> = row.get(1)?;
            items.push(dec_keyed::<T, K>(&blob, what, key, &key_of)?);
        }
        Ok::<_, SqliteError>(items)
    })();
    match res {
        Ok(items) => items.into_iter().map(Ok).collect(),
        Err(e) => vec![Err(e)],
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;
    use std::num::NonZeroU32;
    use std::str::FromStr;

    use rgb::bitcoin::hashes::sha256d::Hash;
    use rgb::bitcoin::{absolute, Txid};
    use rgb::commit_verify::Conceal;
    use rgb::vm::{WitnessOrd, WitnessPos};
    use rgb::{
        AssignmentType, BundleId, Genesis, GlobalStateType, GraphSeal, OpId, Operation, Opout,
        OutputSeal, RevealedData, Schema, SchemaId, TransitionBundle, TransitionType,
    };
    use strict_encoding::{StrictDumb, TypeName};
    use strict_types::stl::{bitcoin_stl, std_stl};

    use super::*;
    use crate::containers::{SealWitness, SpvProof};
    use crate::persistence::{
        AllocKind, AllocSeal, AllocationFilter, AllocationWrite, GlobalStateWrite, RgbStore,
        Visibility,
    };

    fn shared_db() -> SharedDb {
        let conn = Connection::open_in_memory().unwrap();
        schema::migrate(&conn).unwrap();
        Arc::new(Mutex::new(Db { conn }))
    }

    #[test]
    fn store_roundtrip() {
        let mut store = SqliteStore::new(shared_db());

        let schema = Schema::strict_dumb();
        let schema_id = schema.schema_id();
        // put_* are idempotent: a second put of the same value is a no-op
        store.put_schema(&schema).unwrap();
        store.put_schema(&schema).unwrap();
        assert_eq!(store.schema(schema_id).unwrap(), Some(schema.clone()));
        assert!(store.schema(SchemaId::strict_dumb()).unwrap().is_none());

        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema_id;
        let contract_id = genesis.contract_id();
        store.put_genesis(&genesis).unwrap();
        store.put_genesis(&genesis).unwrap();
        assert_eq!(store.genesis(contract_id).unwrap(), Some(genesis.clone()));

        let witness = SealWitness::strict_dumb();
        let witness_id = witness.witness_id();
        store.put_witness(&witness).unwrap();
        store.put_witness(&witness).unwrap();
        assert_eq!(store.witness(witness_id).unwrap(), Some(witness));

        let seal = GraphSeal::strict_dumb();
        store.put_secret_seal(&seal, seal.conceal()).unwrap();
        store.put_secret_seal(&seal, seal.conceal()).unwrap();
        assert_eq!(store.seal_of_secret(seal.conceal()).unwrap(), Some(seal));

        assert_eq!(store.schemata().collect::<Result<Vec<_>, _>>().unwrap(), vec![schema]);
        assert_eq!(store.geneses().collect::<Result<Vec<_>, _>>().unwrap(), vec![genesis]);
    }

    #[test]
    fn rollback_discards_uncommitted_writes() {
        let mut store = SqliteStore::new(shared_db());
        let schema = Schema::strict_dumb();
        let schema_id = schema.schema_id();

        store.begin(TxMode::Write).unwrap();
        store.put_schema(&schema).unwrap();
        store.rollback();

        assert!(store.schema(schema_id).unwrap().is_none());
        assert_eq!(store.schemata().count(), 0);
    }

    /// Every state family survives a write and a read back as itself. The
    /// marker each is stored under must round-trip and must be one the
    /// `state_type` CHECK constraint accepts, or the insert would be rejected.
    #[test]
    fn allocation_kinds_round_trip() {
        let mut store = SqliteStore::new(shared_db());

        let schema = Schema::strict_dumb();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        store.put_schema(&schema).unwrap();
        store.put_genesis(&genesis).unwrap();

        let seal = OutputSeal::with(Txid::strict_dumb(), 0u32);
        let kinds = [AllocKind::Fungible, AllocKind::Structured, AllocKind::Declarative];
        for (no, kind) in kinds.iter().enumerate() {
            store
                .put_allocation(AllocationWrite {
                    contract_id,
                    kind: *kind,
                    opout: Opout::new(
                        OpId::strict_dumb(),
                        AssignmentType::strict_dumb(),
                        no as u16,
                    ),
                    seal: AllocSeal::explicit(seal),
                    bundle_id: None,
                    value: &[],
                })
                .unwrap();
        }

        // each kind is fetched back on its own
        for kind in kinds {
            let rows = store
                .allocations(contract_id, AllocationFilter::all(Visibility::All).kind(kind))
                .unwrap();
            assert_eq!(rows.len(), 1, "{kind:?} must be stored under its own marker");
        }
        // and all of them at once, each tagged with the kind it went in as
        let at_outpoint = store
            .allocations(
                contract_id,
                AllocationFilter::all(Visibility::All).at(&bset![seal.to_outpoint()]),
            )
            .unwrap()
            .into_iter()
            .map(|row| row.kind)
            .collect::<BTreeSet<_>>();
        assert_eq!(at_outpoint, kinds.into_iter().collect::<BTreeSet<_>>());
    }

    /// The narrowings compose: each one is a clause the query gains, and asking
    /// for all of them at once is the intersection, not the last one to win.
    #[test]
    fn allocation_filters_compose() {
        let mut store = SqliteStore::new(shared_db());

        let schema = Schema::strict_dumb();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        store.put_schema(&schema).unwrap();
        store.put_genesis(&genesis).unwrap();

        let here = OutputSeal::with(Txid::strict_dumb(), 0u32);
        let elsewhere =
            OutputSeal::with(Txid::from_raw_hash(*Hash::from_bytes_ref(&[0xEE; 32])), 1u32);
        let ty_a = AssignmentType::with(4000);
        let ty_b = AssignmentType::with(4001);
        // one row per (kind, type, seal) corner, so every clause has something
        // to exclude
        let mut no = 0u16;
        for kind in [AllocKind::Fungible, AllocKind::Structured] {
            for ty in [ty_a, ty_b] {
                for seal in [here, elsewhere] {
                    store
                        .put_allocation(AllocationWrite {
                            contract_id,
                            kind,
                            opout: Opout::new(OpId::strict_dumb(), ty, no),
                            seal: AllocSeal::explicit(seal),
                            bundle_id: None,
                            value: &[],
                        })
                        .unwrap();
                    no += 1;
                }
            }
        }

        let count = |filter| store.allocations(contract_id, filter).unwrap().len();
        let all = AllocationFilter::all(Visibility::All);
        let at_here = bset![here.to_outpoint()];
        let nowhere = bset![];
        assert_eq!(count(all), 8);
        assert_eq!(count(all.kind(AllocKind::Fungible)), 4);
        assert_eq!(count(all.type_id(ty_a)), 4);
        assert_eq!(count(all.at(&at_here)), 4);
        assert_eq!(count(all.kind(AllocKind::Fungible).type_id(ty_a)), 2);
        assert_eq!(count(all.kind(AllocKind::Fungible).type_id(ty_a).at(&at_here)), 1);
        // an empty outpoint set is not "no filter": nothing is a member of it
        assert_eq!(count(all.at(&nowhere)), 0);
        // a family with no rows at all is empty rather than unfiltered
        assert_eq!(count(all.kind(AllocKind::Declarative)), 0);
    }

    /// One query over the shared outpoints returns every contract's
    /// allocations, each tagged with the contract it belongs to, and nothing
    /// pinned to an outpoint outside the request.
    #[test]
    fn all_allocations_at_outpoints_spans_contracts() {
        let mut store = SqliteStore::new(shared_db());

        let schema = Schema::strict_dumb();
        store.put_schema(&schema).unwrap();
        let mut contract_ids = Vec::new();
        for timestamp in [1i64, 2] {
            let mut genesis = Genesis::strict_dumb();
            genesis.schema_id = schema.schema_id();
            genesis.timestamp = timestamp;
            contract_ids.push(genesis.contract_id());
            store.put_genesis(&genesis).unwrap();
        }

        let shared = OutputSeal::with(Txid::strict_dumb(), 0u32);
        let other = OutputSeal::with(Txid::strict_dumb(), 1u32);
        for (no, seal) in [shared, other].into_iter().enumerate() {
            for contract_id in &contract_ids {
                store
                    .put_allocation(AllocationWrite {
                        contract_id: *contract_id,
                        kind: AllocKind::Declarative,
                        opout: Opout::new(
                            OpId::strict_dumb(),
                            AssignmentType::strict_dumb(),
                            no as u16,
                        ),
                        seal: AllocSeal::explicit(seal),
                        bundle_id: None,
                        value: &[],
                    })
                    .unwrap();
            }
        }

        let rows = store
            .all_allocations_at_outpoints(&bset![shared.to_outpoint()], Visibility::All)
            .unwrap();
        assert_eq!(rows.len(), contract_ids.len());
        assert_eq!(
            rows.iter().map(|(id, ..)| *id).collect::<BTreeSet<_>>(),
            contract_ids.iter().copied().collect::<BTreeSet<_>>()
        );
        assert!(rows
            .iter()
            .all(|(.., row)| row.seal == AllocSeal::explicit(shared)));
    }

    #[test]
    fn op_inputs_round_trip() {
        let mut store = SqliteStore::new(shared_db());

        // The child bundle must be stored for the op_inputs.bundle_id FK
        let wbundle = TransitionBundle::strict_dumb();
        let bundle = wbundle.bundle_id();
        store.put_bundle(&wbundle).unwrap();

        let parent_a = OpId::from([0xAA; 32]);
        let parent_b = OpId::from([0xBB; 32]);
        let child = OpId::from([0xCC; 32]);
        let (ty0, ty1) = (AssignmentType::with(0), AssignmentType::with(1));

        let in0 = Opout::new(parent_a, ty0, 0);
        let in1 = Opout::new(parent_a, ty0, 1);
        let in2 = Opout::new(parent_b, ty1, 0);

        store.put_op_input(in0, child, bundle).unwrap();
        store.put_op_input(in1, child, bundle).unwrap();
        store.put_op_input(in2, child, bundle).unwrap();

        // Backward: every opout the child transition spends, including two from
        // the same producer
        assert_eq!(store.input_opouts_for_op(child).unwrap(), BTreeSet::from([in0, in1, in2]));
        assert!(store.input_opouts_for_op(parent_a).unwrap().is_empty());

        // Forward: which bundles spend a producing op's outputs
        assert_eq!(store.child_bundles_of_op(parent_a).unwrap(), BTreeSet::from([bundle]));
        assert_eq!(store.child_bundles_of_op(parent_b).unwrap(), BTreeSet::from([bundle]));
        assert!(store.child_bundles_of_op(child).unwrap().is_empty());
    }

    // also doubles as a check that `PRAGMA foreign_keys` has been enabled
    #[test]
    fn deferred_fk_enforced_at_commit() {
        let mut store = SqliteStore::new(shared_db());
        let spent = Opout::new(OpId::from([1; 32]), AssignmentType::with(0), 0);
        let child = OpId::from([2; 32]);
        let wbundle = TransitionBundle::strict_dumb();
        let bundle = wbundle.bundle_id();

        // Deferred: inside one transaction the child (op_inputs) may be written
        // BEFORE its parent bundle; the FK is only checked at COMMIT
        store.begin(TxMode::Write).unwrap();
        store.put_op_input(spent, child, bundle).unwrap();
        store.put_bundle(&wbundle).unwrap();
        store.commit().unwrap();

        // Orphan: a spend naming a bundle that is never stored fails at COMMIT
        store.begin(TxMode::Write).unwrap();
        store
            .put_op_input(
                Opout::new(OpId::from([3; 32]), AssignmentType::with(0), 0),
                OpId::from([4; 32]),
                BundleId::from([0x99; 32]), // no bundles row
            )
            .unwrap();
        assert!(store.commit().is_err());
        store.rollback();
    }

    #[test]
    fn sqlite_stock_opens() {
        let stock = SqliteStock::in_memory().unwrap();
        assert_eq!(stock.as_store().schemata().count(), 0);
    }

    /// A store record filed under a key it does not derive is refused rather
    /// than returned. The key column and the blob are the one place the schema
    /// keeps the same fact twice, so it is the one place they can disagree.
    #[test]
    fn record_filed_under_a_foreign_key_is_refused() {
        let db = shared_db();
        let mut store = SqliteStore::new(db.clone());

        let witness = SealWitness::strict_dumb();
        store.put_witness(&witness).unwrap();

        // re-file the very same witness under someone else's txid, as a
        // backend bug or a corrupted copy would
        let foreign = Txid::from_raw_hash(*Hash::from_bytes_ref(&[0xEE; 32]));
        db.lock()
            .unwrap()
            .conn
            .execute("UPDATE witness SET txid = ?1", [codec::encode(&foreign).unwrap()])
            .unwrap();

        let err = store.witness(foreign).unwrap_err();
        assert!(
            matches!(err, SqliteError::Integrity(_)),
            "a witness under a foreign txid must not be handed back: {err:?}"
        );
    }

    /// Type libraries are stored once and linked to every schema defined by
    /// them, and each comes back checked against its own commitment - the same
    /// treatment AluVM libraries get, and the reason the type system is derived
    /// from these rather than stored.
    #[test]
    fn type_libs_are_shared_and_keyed_by_their_commitment() {
        let db = shared_db();
        let mut store = SqliteStore::new(db.clone());

        let schema = Schema::strict_dumb();
        let mut other = Schema::strict_dumb();
        other.name = TypeName::from_str("Other").unwrap();
        let (schema_id, other_id) = (schema.schema_id(), other.schema_id());
        assert_ne!(schema_id, other_id);
        store.put_schema(&schema).unwrap();
        store.put_schema(&other).unwrap();

        // one library, linked to both schemata; both halves are idempotent
        let lib = std_stl();
        store.put_type_lib(schema_id, &lib).unwrap();
        store.put_type_lib(schema_id, &lib).unwrap();
        store.put_type_lib(other_id, &lib).unwrap();
        assert_eq!(store.type_libs(schema_id).unwrap(), bmap! { lib.id() => lib.clone() });
        assert_eq!(store.type_libs(other_id).unwrap(), bmap! { lib.id() => lib.clone() });
        assert_eq!(
            db.lock()
                .unwrap()
                .conn
                .query_row("SELECT count(*) FROM type_lib", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1,
            "a shared library must be stored once"
        );

        // a library whose content no longer derives the id it is filed under is
        // refused rather than handed back - the check a stored type system,
        // whose semantic ids commit to names it does not carry, cannot get
        let foreign = bitcoin_stl();
        assert_ne!(foreign.id(), lib.id());
        db.lock()
            .unwrap()
            .conn
            .execute("UPDATE type_lib SET type_lib_blob = ?1", [codec::encode(&foreign).unwrap()])
            .unwrap();
        let err = store.type_libs(schema_id).unwrap_err();
        assert!(
            matches!(err, SqliteError::Integrity(_)),
            "a swapped type library must not be handed back: {err:?}"
        );
    }

    /// A row the schema forbids must be reported, not dropped. `INSERT OR
    /// IGNORE` ignores CHECK and NOT NULL violations as readily as duplicate
    /// keys, so a malformed write did nothing and said nothing - which is how a
    /// test asserting on stored rows stayed red while the query it blamed was
    /// fine. Naming the conflict target keeps the idempotent replay and lets
    /// everything else through.
    #[test]
    fn a_row_the_check_forbids_is_reported() {
        let mut store = SqliteStore::new(shared_db());
        let schema = Schema::strict_dumb();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        store.put_schema(&schema).unwrap();
        store.put_genesis(&genesis).unwrap();

        let type_id = GlobalStateType::strict_dumb();
        let half_a_bundle = GlobalStateWrite {
            contract_id,
            type_id,
            opid: OpId::strict_dumb(),
            index: 0,
            nonce: 0,
            // the CHECK pairs these two: a bundle without its transition type
            bundle_id: Some(BundleId::strict_dumb()),
            transition_type: None,
            value: &RevealedData::strict_dumb(),
        };
        let err = store
            .put_global(half_a_bundle)
            .expect_err("a row the CHECK forbids must not be written off in silence");
        assert!(
            format!("{err}").contains("CHECK"),
            "the constraint which refused the row should be named: {err}"
        );
        assert!(
            store
                .globals(contract_id, type_id, Visibility::All)
                .unwrap()
                .is_empty(),
            "and nothing should have been stored"
        );
    }

    /// A nonce is a `u64`, and the column holding it is SQLite's INTEGER: a
    /// signed 64-bit value. Everything from `2^63` up therefore sits on disk as
    /// a negative number.
    /// What makes that sound is that the bit-cast on either side of the column
    /// is exact, and that no SQL ever compares the stored value: ordering is
    /// the caller's, over the `u64` reassembled here.
    #[test]
    fn nonces_above_i64_max_round_trip() {
        let mut store = SqliteStore::new(shared_db());

        let schema = Schema::strict_dumb();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        store.put_schema(&schema).unwrap();
        store.put_genesis(&genesis).unwrap();

        let bundle = TransitionBundle::strict_dumb();
        let bundle_id = bundle.bundle_id();
        store.put_bundle(&bundle).unwrap();

        let type_id = GlobalStateType::strict_dumb();
        let value = RevealedData::strict_dumb();
        let nonces = [0u64, 1, i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX];
        // one row per nonce, told apart by `index`: the UNIQUE key over the
        // table is (contract, type, op, index)
        for (index, nonce) in nonces.iter().enumerate() {
            store
                .put_global(GlobalStateWrite {
                    contract_id,
                    type_id,
                    opid: OpId::strict_dumb(),
                    index: index as u16,
                    nonce: *nonce,
                    bundle_id: Some(bundle_id),
                    transition_type: Some(TransitionType::strict_dumb()),
                    value: &value,
                })
                .unwrap();
        }

        let mut stored = store
            .globals(contract_id, type_id, Visibility::All)
            .unwrap();
        stored.sort_by_key(|row| row.index);
        assert_eq!(
            stored.iter().map(|row| row.nonce).collect::<Vec<_>>(),
            nonces,
            "every nonce must come back as it went in, wrapped or not"
        );
    }

    /// `Visibility::Valid` is answered by the store: an allocation whose bundle
    /// has no witness the store can place, or only archived ones, or whose
    /// operation is marked invalid, does not come back - while `All` still
    /// returns it.
    #[test]
    fn visibility_filters_allocations_in_the_query() {
        let mut store = SqliteStore::new(shared_db());

        let schema = Schema::strict_dumb();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        store.put_schema(&schema).unwrap();
        store.put_genesis(&genesis).unwrap();

        let witness = SealWitness::strict_dumb();
        let witness_id = witness.witness_id();
        store.put_witness(&witness).unwrap();
        let bundle = TransitionBundle::strict_dumb();
        let bundle_id = bundle.bundle_id();
        store.put_bundle(&bundle).unwrap();
        store.put_bundle_witness(bundle_id, witness_id).unwrap();

        let seal = OutputSeal::with(Txid::strict_dumb(), 0u32);
        let ty = AssignmentType::strict_dumb();
        let opid = OpId::strict_dumb();
        let alloc = |bundle_id: Option<BundleId>, no: u16| AllocationWrite {
            contract_id,
            kind: AllocKind::Declarative,
            opout: Opout::new(opid, ty, no),
            seal: AllocSeal::explicit(seal),
            bundle_id,
            value: &[],
        };
        // one from the bundle above, one from genesis
        store.put_allocation(alloc(Some(bundle_id), 0)).unwrap();
        store.put_allocation(alloc(None, 1)).unwrap();

        let visible = |store: &SqliteStore| {
            store
                .allocations(
                    contract_id,
                    AllocationFilter::all(Visibility::Valid).kind(AllocKind::Declarative),
                )
                .unwrap()
                .len()
        };
        let all = |store: &SqliteStore| {
            store
                .allocations(
                    contract_id,
                    AllocationFilter::all(Visibility::All).kind(AllocKind::Declarative),
                )
                .unwrap()
                .len()
        };

        // no WitnessOrd yet: state whose bundle has no witness the store can
        // place is not visible, while the genesis row always is
        assert_eq!(visible(&store), 1);
        assert_eq!(all(&store), 2);

        store
            .put_witness_ord(witness_id, WitnessOrd::Tentative)
            .unwrap();
        assert_eq!(visible(&store), 2);

        store
            .put_witness_ord(witness_id, WitnessOrd::Archived)
            .unwrap();
        assert_eq!(visible(&store), 1, "an archived witness hides its allocations");
        assert_eq!(all(&store), 2, "and Visibility::All still sees them");

        // the operation produces both rows, so invalidating it hides the
        // genesis one too
        store
            .put_witness_ord(witness_id, WitnessOrd::Tentative)
            .unwrap();
        store.set_op_validity(opid, false).unwrap();
        assert_eq!(visible(&store), 0);
        assert_eq!(all(&store), 2);
    }

    /// A seal on the witness transaction is stored once and lands on every
    /// witness of its bundle: a whole read returns it as defined, a read at an
    /// outpoint returns it resolved to that outpoint, and archiving one witness
    /// removes only that witness's outpoint. Two assignments on the same output
    /// of one bundle are both found.
    #[test]
    fn witness_seal_lands_on_every_witness() {
        let mut store = SqliteStore::new(shared_db());

        let schema = Schema::strict_dumb();
        let mut genesis = Genesis::strict_dumb();
        genesis.schema_id = schema.schema_id();
        let contract_id = genesis.contract_id();
        store.put_schema(&schema).unwrap();
        store.put_genesis(&genesis).unwrap();

        let bundle = TransitionBundle::strict_dumb();
        let bundle_id = bundle.bundle_id();
        store.put_bundle(&bundle).unwrap();
        let witness_ids = [1u8, 2].map(|nonce| {
            let mut witness = SealWitness::strict_dumb();
            witness.tx.lock_time = absolute::LockTime::from_consensus(nonce as u32);
            let id = witness.witness_id();
            store.put_witness(&witness).unwrap();
            store.put_bundle_witness(bundle_id, id).unwrap();
            store.put_witness_ord(id, WitnessOrd::Tentative).unwrap();
            id
        });

        let vout = 3u32;
        let alloc = |no: u16, bundle_id: Option<BundleId>| AllocationWrite {
            contract_id,
            kind: AllocKind::Declarative,
            opout: Opout::new(OpId::strict_dumb(), AssignmentType::strict_dumb(), no),
            seal: AllocSeal::witness_vout(vout),
            bundle_id,
            value: &[],
        };
        for no in [0, 1] {
            store.put_allocation(alloc(no, Some(bundle_id))).unwrap();
        }
        // consumed again under the other witness: the same row, not a new one
        store.put_allocation(alloc(0, Some(bundle_id))).unwrap();
        // genesis has no witness for such a seal to land on
        assert!(store.put_allocation(alloc(2, None)).is_err());

        let whole = |store: &SqliteStore| {
            store
                .allocations(contract_id, AllocationFilter::all(Visibility::Valid))
                .unwrap()
        };
        let rows = whole(&store);
        assert_eq!(rows.len(), 2, "one row per assignment, not per witness");
        assert!(rows
            .iter()
            .all(|row| row.seal == AllocSeal::witness_vout(vout)));

        let at = |store: &SqliteStore, txid: Txid, vout: u32, visibility| {
            let outpoints = bset![rgb::bitcoin::OutPoint::new(txid, vout)];
            let rows = store
                .allocations(contract_id, AllocationFilter::all(visibility).at(&outpoints))
                .unwrap();
            let across = store
                .all_allocations_at_outpoints(&outpoints, visibility)
                .unwrap();
            assert_eq!(rows.len(), across.len(), "both outpoint reads must agree");
            let resolved = AllocSeal::explicit(OutputSeal::with(txid, vout));
            assert!(rows.iter().all(|row| row.seal == resolved));
            rows.len()
        };
        for id in witness_ids {
            assert_eq!(at(&store, id, vout, Visibility::Valid), 2);
            assert_eq!(at(&store, id, vout + 1, Visibility::Valid), 0);
        }

        store
            .put_witness_ord(witness_ids[1], WitnessOrd::Archived)
            .unwrap();
        assert_eq!(at(&store, witness_ids[1], vout, Visibility::Valid), 0);
        assert_eq!(at(&store, witness_ids[1], vout, Visibility::All), 2);
        assert_eq!(at(&store, witness_ids[0], vout, Visibility::Valid), 2);
        assert_eq!(whole(&store).len(), 2, "the bundle is still validly witnessed");
    }

    /// The membership question and the whole-table read must agree, since the
    /// first is what decides whether the second is worth doing.
    #[test]
    fn any_op_invalid_agrees_with_the_full_read() {
        let mut store = SqliteStore::new(shared_db());

        let invalid = OpId::strict_dumb();
        let untouched = OpId::from([0x77; 32]);

        // nothing is invalid yet, whatever is asked about
        assert!(!store.any_op_invalid(&bset![invalid, untouched]).unwrap());
        assert!(store.all_invalid_ops().unwrap().is_empty());

        store.set_op_validity(invalid, false).unwrap();
        assert!(store.any_op_invalid(&bset![invalid]).unwrap());
        assert!(store.any_op_invalid(&bset![invalid, untouched]).unwrap());
        // a set the invalidation did not touch stays false even though the
        // table is no longer empty
        assert!(!store.any_op_invalid(&bset![untouched]).unwrap());
        // asking about nothing is not asking whether anything is invalid
        assert!(!store.any_op_invalid(&bset![]).unwrap());
        assert_eq!(store.all_invalid_ops().unwrap(), bset![invalid]);

        store.set_op_validity(invalid, true).unwrap();
        assert!(!store.any_op_invalid(&bset![invalid]).unwrap());
        assert!(store.all_invalid_ops().unwrap().is_empty());
    }

    /// Every [`WitnessOrd`] survives the trip through its columns, and the
    /// batch and refresh-candidate reads agree with the single-row one.
    #[test]
    fn witness_ords_round_trip_and_narrow() {
        let mut store = SqliteStore::new(shared_db());

        let mined = |height: u32| {
            WitnessOrd::Mined(
                WitnessPos::bitcoin(NonZeroU32::new(height).unwrap(), 1231006505 + height as i64)
                    .unwrap(),
            )
        };
        let cases = [
            (1u8, mined(10)),
            (2, mined(900_000)),
            (3, WitnessOrd::Tentative),
            (4, WitnessOrd::Ignored),
            (5, WitnessOrd::Archived),
        ];
        let mut ids = BTreeSet::new();
        for (nonce, ord) in cases {
            let mut witness = SealWitness::strict_dumb();
            witness.tx.lock_time = absolute::LockTime::from_consensus(nonce as u32);
            let id = witness.witness_id();
            store.put_witness(&witness).unwrap();
            store.put_witness_ord(id, ord).unwrap();
            assert_eq!(store.witness_ord(id).unwrap(), Some(ord), "{ord:?} must round-trip");
            ids.insert(id);
        }

        // the batch read answers for exactly the ids asked about
        let asked: BTreeSet<Txid> = ids.iter().take(2).copied().collect();
        assert_eq!(store.witness_ords(&asked).unwrap().len(), 2);
        assert!(store.witness_ords(&bset![]).unwrap().is_empty());
        assert_eq!(store.all_witness_ords().unwrap().len(), cases.len());

        // refresh candidates: everything but the ignored one and the shallowly
        // mined one
        let candidates = store
            .witness_ords_to_refresh(NonZeroU32::new(1000).unwrap())
            .unwrap();
        let statuses: BTreeSet<WitnessOrd> = store
            .witness_ords(&candidates)
            .unwrap()
            .into_values()
            .collect();
        assert_eq!(statuses, bset![mined(900_000), WitnessOrd::Tentative, WitnessOrd::Archived]);
    }

    /// The SPV proof is written and read without the witness around it, and
    /// only a real change rewrites the row.
    #[test]
    fn spv_proof_is_stored_beside_its_witness() {
        let mut store = SqliteStore::new(shared_db());

        let mut witness = SealWitness::strict_dumb();
        witness.spv_proof = None;
        let id = witness.witness_id();
        store.put_witness(&witness).unwrap();
        assert_eq!(store.witness_spv_proof(id).unwrap(), None);

        let proof = SpvProof::strict_dumb();
        assert!(store.set_witness_spv_proof(id, Some(&proof)).unwrap());
        // a second write of the same proof changes nothing, which is what the
        // caller reports back as "nothing happened"
        assert!(!store.set_witness_spv_proof(id, Some(&proof)).unwrap());
        assert_eq!(store.witness_spv_proof(id).unwrap(), Some(proof.clone()));

        // and the rest of the witness came through untouched
        let stored = store.witness(id).unwrap().unwrap();
        assert_eq!(stored.tx, witness.tx);
        assert_eq!(stored.mpc_merkle_block, witness.mpc_merkle_block);
        assert_eq!(stored.dbc_proof, witness.dbc_proof);
        assert_eq!(stored.spv_proof, Some(proof));

        assert!(store.set_witness_spv_proof(id, None).unwrap());
        assert_eq!(store.witness_spv_proof(id).unwrap(), None);
        // an unknown witness is left alone rather than conjured into existence
        assert!(!store
            .set_witness_spv_proof(
                Txid::from_raw_hash(*Hash::from_bytes_ref(&[0xAB; 32])),
                Some(&SpvProof::strict_dumb())
            )
            .unwrap());
    }

    /// The op->bundle and bundle->witness indexes answer in both directions.
    #[test]
    fn index_lookups_reverse() {
        let mut store = SqliteStore::new(shared_db());
        let bundle = TransitionBundle::strict_dumb();
        let bundle_id = bundle.bundle_id();
        store.put_bundle(&bundle).unwrap();

        let opids = bset![OpId::from([1; 32]), OpId::from([2; 32])];
        for opid in &opids {
            store.put_op_bundle(*opid, bundle_id).unwrap();
        }

        assert_eq!(store.ops_in_bundle(bundle_id).unwrap(), opids);
        assert!(store
            .ops_in_bundle(BundleId::from([9; 32]))
            .unwrap()
            .is_empty());
        for opid in &opids {
            assert_eq!(store.bundle_of_op(*opid).unwrap(), Some(bundle_id));
        }

        let witness = SealWitness::strict_dumb();
        let witness_id = witness.witness_id();
        store.put_witness(&witness).unwrap();
        store.put_bundle_witness(bundle_id, witness_id).unwrap();

        assert_eq!(store.bundles_of_witness(witness_id).unwrap(), bset![bundle_id]);
        assert_eq!(store.bundle_witnesses(bundle_id).unwrap(), bset![witness_id]);
        assert!(store
            .bundles_of_witness(Txid::from_raw_hash(*Hash::from_bytes_ref(&[0x99; 32])))
            .unwrap()
            .is_empty());
    }
}
