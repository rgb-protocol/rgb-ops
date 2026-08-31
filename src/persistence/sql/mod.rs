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

//! SQLite-backed implementation of the [`crate::persistence`] providers.
//!
//! All three providers share a single [`rusqlite::Connection`], so a Stock
//! store transaction maps onto exactly one SQL transaction covering stash,
//! state and index together.

mod schema;
mod stash;
mod state;
mod index;

use std::collections::VecDeque;
use std::io::BufRead;
use std::iter;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use amplify::confinement::U32 as U32MAX;
use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection, Row};
use strict_encoding::{DecodeError, StrictDecode, StrictEncode, StrictReader, StrictWriter};

pub use self::index::SqlIndex;
pub use self::stash::SqlStash;
pub use self::state::{SqlContractReader, SqlContractWriter, SqlState};
use crate::persistence::Stock;

/// Stock persisting all of its providers in a single SQLite database.
pub type SqliteStock = Stock<SqlStash, SqlState, SqlIndex>;

/// Opens (creating and migrating when needed) a SQLite-backed stock at the
/// given database file path.
pub fn open(path: impl AsRef<Path>) -> Result<SqliteStock, SqlError> {
    with_connection(Connection::open(path)?)
}

/// Creates a transient in-memory SQLite-backed stock (mostly useful for
/// testing).
pub fn open_in_memory() -> Result<SqliteStock, SqlError> {
    with_connection(Connection::open_in_memory()?)
}

fn with_connection(conn: Connection) -> Result<SqliteStock, SqlError> {
    schema::migrate(&conn)?;
    let db = Arc::new(Mutex::new(Db { conn, in_tx: false }));
    Ok(Stock::with(SqlStash::new(db.clone()), SqlState::new(db.clone()), SqlIndex::new(db)))
}

/// Error type for the SQLite persistence providers.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error)]
#[display("SQLite storage error: {0}")]
pub struct SqlError(String);

impl SqlError {
    fn poisoned() -> Self { SqlError(s!("database mutex is poisoned")) }
}

impl From<rusqlite::Error> for SqlError {
    fn from(err: rusqlite::Error) -> Self { SqlError(err.to_string()) }
}

impl From<DecodeError> for SqlError {
    fn from(err: DecodeError) -> Self { SqlError(format!("cannot decode stored data: {err}")) }
}

/// Shared database handle: the connection plus the state of the single SQL
/// transaction shared by all three providers.
#[derive(Debug)]
struct Db {
    conn: Connection,
    in_tx: bool,
}

type SharedDb = Arc<Mutex<Db>>;

fn lock(db: &SharedDb) -> Result<MutexGuard<'_, Db>, SqlError> {
    db.lock().map_err(|_| SqlError::poisoned())
}

impl Db {
    /// Idempotent begin: the first call opens the shared SQL transaction,
    /// subsequent calls from the other providers are no-ops.
    fn begin(&mut self) -> Result<(), SqlError> {
        if !self.in_tx {
            if !self.conn.is_autocommit() {
                // Heal a transaction leaked by an earlier aborted operation
                self.conn.execute_batch("ROLLBACK")?;
            }
            // FIXME: this would break if in_tx and db state diverge
            self.conn.execute_batch("BEGIN")?;
            self.in_tx = true;
        }
        Ok(())
    }

    /// The first commit call performs the real `COMMIT`, atomically covering
    /// the writes of all three providers; subsequent calls are no-ops.
    fn commit(&mut self) -> Result<(), SqlError> {
        if self.in_tx {
            self.in_tx = false;
            self.conn.execute_batch("COMMIT")?;
        }
        Ok(())
    }

    /// Idempotent rollback of the shared transaction.
    fn rollback(&mut self) {
        if self.in_tx || !self.conn.is_autocommit() {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
        self.in_tx = false;
    }

    /// Runs a single-blob-column keyed lookup, mapping the no-rows case to
    /// `None`.
    fn blob(&self, sql: &str, key: &[u8]) -> Result<Option<Vec<u8>>, SqlError> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        match stmt.query_row([key], |row| row.get::<_, Vec<u8>>(0)) {
            Ok(blob) => Ok(Some(blob)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Checks whether a keyed row exists.
    fn exists(&self, sql: &str, key: &[u8]) -> Result<bool, SqlError> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        stmt.exists([key]).map_err(SqlError::from)
    }
}

/// Strict-encodes a value into a blob stored in the database.
fn enc(val: &impl StrictEncode) -> Result<Vec<u8>, SqlError> {
    let writer = StrictWriter::in_memory::<U32MAX>();
    let writer = val
        .strict_encode(writer)
        .map_err(|e| SqlError(format!("cannot serialize data: {e}")))?;
    Ok(writer.unbox().unconfine())
}

/// Strict-decodes a blob retrieved from the database, ensuring it is consumed
/// in full.
fn dec<T: StrictDecode>(blob: &[u8]) -> Result<T, SqlError> {
    let mut reader = StrictReader::in_memory::<U32MAX>(blob);
    let val = T::strict_decode(&mut reader)?;
    let mut cursor = reader.into_cursor();
    if !cursor
        .fill_buf()
        .map_err(|e| SqlError(e.to_string()))?
        .is_empty()
    {
        return Err(SqlError(s!("stored data not entirely consumed by decoder")));
    }
    Ok(val)
}

/// Number of rows fetched by a single [`SqlKeyCursor`] refill.
const BATCH_SIZE: usize = 64;

/// Row mapper used by [`SqlKeyCursor`]: extracts the keyset cursor key and the
/// decoded item from a fetched row.
type RowMapper<T> = fn(&Row<'_>) -> Result<(Value, T), SqlError>;

/// Maps a `(key, blob)` row into the raw key plus the strict-decoded item.
fn map_decode<T: StrictDecode>(row: &Row<'_>) -> Result<(Value, T), SqlError> {
    let key: Vec<u8> = row.get(0).map_err(SqlError::from)?;
    let blob: Vec<u8> = row.get(1).map_err(SqlError::from)?;
    Ok((Value::Blob(key), dec(&blob)?))
}

/// Lazy keyset-pagination iterator over an unbounded table scan.
///
/// The cursor owns everything it needs — the shared database handle, its SQL
/// text (which must select the keyset key as the first column, filter on
/// `key > ?1`, order by the key and limit to [`BATCH_SIZE`] rows) and the
/// values bound to any extra `?2..` placeholders — so no borrow ever crosses
/// the connection mutex: each refill locks, fetches and decodes one batch,
/// and unlocks. Memory usage is O(batch) regardless of the table size.
struct SqlKeyCursor<T> {
    db: SharedDb,
    sql: String,
    params: Vec<Value>,
    last_key: Value,
    map: RowMapper<T>,
    buf: VecDeque<Result<T, SqlError>>,
    done: bool,
}

impl<T> SqlKeyCursor<T> {
    /// Creates a cursor; `sql` must bind the keyset key as `?1` and the given
    /// extra parameters as `?2..`.
    fn new(db: SharedDb, sql: String, params: Vec<Value>, map: RowMapper<T>) -> Self {
        Self {
            db,
            sql,
            params,
            // An empty blob sorts before every non-empty key in SQLite
            last_key: Value::Blob(vec![]),
            map,
            buf: VecDeque::new(),
            done: false,
        }
    }

    fn refill(&mut self) {
        let res = (|| {
            let db = lock(&self.db)?;
            let mut stmt = db.conn.prepare_cached(&self.sql)?;
            let mut rows =
                stmt.query(params_from_iter(iter::once(&self.last_key).chain(self.params.iter())))?;
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            loop {
                let Some(row) = rows.next()? else { break };
                batch.push((self.map)(row)?);
            }
            Ok::<_, SqlError>(batch)
        })();
        match res {
            Ok(batch) => {
                if batch.len() < BATCH_SIZE {
                    self.done = true;
                }
                for (key, item) in batch {
                    self.last_key = key;
                    self.buf.push_back(Ok(item));
                }
            }
            Err(e) => {
                self.done = true;
                self.buf.push_back(Err(e));
            }
        }
    }
}

impl<T> Iterator for SqlKeyCursor<T> {
    type Item = Result<T, SqlError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() && !self.done {
            self.refill();
        }
        self.buf.pop_front()
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use amplify::ByteArray;
    use rgb::bitcoin::OutPoint as Outpoint;
    use rgb::commit_verify::Conceal;
    use rgb::vm::WitnessOrd;
    use rgb::{
        Assign, AssignmentType, BundleId, ContractId, ExposedSeal, Genesis, GenesisSeal, GraphSeal,
        OpId, Operation, Opout, Schema, SchemaId, Txid, VoidState,
    };
    use strict_encoding::StrictDumb;

    use super::*;
    use crate::containers::SealWitness;
    use crate::persistence::{
        ContractStateRead, IndexInconsistency, IndexReadError, IndexReadProvider, IndexWriteError,
        IndexWriteProvider, StashReadProvider, StashWriteProvider, StateReadProvider,
        StateWriteProvider,
    };

    fn shared_db() -> SharedDb {
        let conn = Connection::open_in_memory().unwrap();
        schema::migrate(&conn).unwrap();
        Arc::new(Mutex::new(Db { conn, in_tx: false }))
    }

    #[test]
    fn stash_roundtrips() {
        let db = shared_db();
        let mut stash = SqlStash::new(db);

        let schema = Schema::strict_dumb();
        let schema_id = schema.schema_id();
        assert!(stash.replace_schema(schema.clone()).unwrap());
        // Schemas are insert-if-absent
        assert!(!stash.replace_schema(schema.clone()).unwrap());
        assert_eq!(stash.schema(schema_id).unwrap(), schema);
        assert!(stash.schema(SchemaId::strict_dumb()).is_err());
        let all = stash.schemata().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(all, vec![schema]);

        let genesis = Genesis::strict_dumb();
        let contract_id = genesis.contract_id();
        assert!(stash.replace_genesis(genesis.clone()).unwrap());
        assert!(!stash.replace_genesis(genesis.clone()).unwrap());
        assert_eq!(stash.genesis(contract_id).unwrap(), genesis);

        let witness = SealWitness::strict_dumb();
        let witness_id = witness.witness_id();
        assert!(stash.replace_witness(witness.clone()).unwrap());
        assert!(!stash.replace_witness(witness.clone()).unwrap());
        assert_eq!(stash.witness(witness_id).unwrap(), witness);
        assert_eq!(stash.witness_ids().unwrap().collect::<Vec<_>>(), vec![witness_id]);

        let seal = GraphSeal::strict_dumb();
        assert!(stash.add_secret_seal(seal).unwrap());
        assert!(!stash.add_secret_seal(seal).unwrap());
        assert_eq!(stash.seal_secret(seal.conceal()).unwrap(), Some(seal));
    }

    #[test]
    fn shared_transaction_is_atomic_across_providers() {
        let db = shared_db();
        let mut stash = SqlStash::new(db.clone());
        let mut index = SqlIndex::new(db.clone());
        let mut state = SqlState::new(db);

        let schema = Schema::strict_dumb();
        let schema_id = schema.schema_id();
        let contract_id = ContractId::strict_dumb();

        // Begin on every provider, write through two of them, then roll back
        // through the third: nothing must persist
        stash.begin_transaction().unwrap();
        index.begin_transaction().unwrap();
        state.begin_transaction().unwrap();
        stash.replace_schema(schema.clone()).unwrap();
        index.register_contract(contract_id).unwrap();
        state.rollback_transaction();
        assert!(stash.schema(schema_id).is_err());
        assert!(matches!(
            index.public_opouts(contract_id),
            Err(IndexReadError::Inconsistency(IndexInconsistency::ContractAbsent(_)))
        ));

        // Same writes again, this time committed: the first commit makes the
        // writes of all providers durable, the remaining commits are no-ops
        state.begin_transaction().unwrap();
        stash.begin_transaction().unwrap();
        index.begin_transaction().unwrap();
        stash.replace_schema(schema.clone()).unwrap();
        index.register_contract(contract_id).unwrap();
        index.commit_transaction().unwrap();
        state.commit_transaction().unwrap();
        stash.commit_transaction().unwrap();
        assert_eq!(stash.schema(schema_id).unwrap(), schema);
        assert_eq!(index.public_opouts(contract_id).unwrap(), BTreeSet::new());
    }

    #[test]
    fn index_tracks_bundles_operations_and_assignments() {
        let db = shared_db();
        let mut index = SqlIndex::new(db);

        let contract_id = ContractId::strict_dumb();
        let other_contract = ContractId::from_byte_array([0xCA; 32]);
        let bundle_id = BundleId::strict_dumb();
        let witness_id = Txid::strict_dumb();
        let opid = OpId::strict_dumb();

        assert!(index.register_contract(contract_id).unwrap());
        assert!(!index.register_contract(contract_id).unwrap());

        assert!(index
            .register_bundle(bundle_id, witness_id, contract_id)
            .unwrap());
        assert!(!index
            .register_bundle(bundle_id, witness_id, contract_id)
            .unwrap());
        assert!(matches!(
            index.register_bundle(bundle_id, witness_id, other_contract),
            Err(IndexWriteError::Inconsistency(IndexInconsistency::DistinctBundleContract { .. }))
        ));
        let (witnesses, found_contract) = index.bundle_info(bundle_id).unwrap();
        assert_eq!(witnesses, bset![witness_id]);
        assert_eq!(found_contract, contract_id);

        assert!(index.register_operation(opid, bundle_id).unwrap());
        assert!(!index.register_operation(opid, bundle_id).unwrap());
        assert_eq!(index.bundle_id_for_op(opid).unwrap(), bundle_id);

        assert!(!index.register_spending(opid, bundle_id).unwrap());
        assert!(index.register_spending(opid, bundle_id).unwrap());
        assert_eq!(index.bundle_ids_children_of_op(opid).unwrap().len(), 1);

        // Genesis assignment indexing: revealed seals land in the outpoint
        // index, retrievable by outpoint
        let seal = GenesisSeal::strict_dumb();
        let assignments = [Assign::revealed(seal, VoidState::strict_dumb())];
        let type_id = AssignmentType::strict_dumb();
        index
            .index_genesis_assignments(contract_id, &assignments, opid, type_id)
            .unwrap();
        let outpoint = seal.to_output_seal().unwrap().to_outpoint();
        let opouts = index.opouts_by_outputs(contract_id, [outpoint]).unwrap();
        assert_eq!(opouts, bset![Opout::new(opid, type_id, 0)]);
        let assigning = index.contracts_assigning(bset![outpoint]).unwrap();
        assert_eq!(assigning, bset![contract_id]);
        let unknown = Outpoint::new(Txid::strict_dumb(), 0xbeef);
        assert!(matches!(
            index.opouts_by_outputs(contract_id, [unknown]),
            Err(IndexReadError::Inconsistency(IndexInconsistency::OutpointUnknown(..)))
        ));
    }

    #[test]
    fn state_persists_contract_states_and_witness_ords() {
        let db = shared_db();
        let mut state = SqlState::new(db);

        let schema = Schema::strict_dumb();
        let genesis = Genesis::strict_dumb();
        let contract_id = genesis.contract_id();

        assert!(state.update_contract(contract_id).unwrap().is_none());
        let writer = state.register_contract(&schema, &genesis).unwrap();
        drop(writer);
        assert!(state.update_contract(contract_id).unwrap().is_some());
        let contract = state.contract_state(contract_id).unwrap();
        assert_eq!(contract.contract_id(), contract_id);
        assert_eq!(contract.schema_id(), schema.schema_id());

        let witness_id = Txid::strict_dumb();
        assert_eq!(state.witness_ord(witness_id).unwrap(), None);
        state
            .upsert_witness(witness_id, WitnessOrd::Archived)
            .unwrap();
        assert_eq!(state.witness_ord(witness_id).unwrap(), Some(WitnessOrd::Archived));
        assert_eq!(state.all_witness_ords().unwrap().len(), 1);

        let opid = OpId::strict_dumb();
        assert!(!state.invalid_ops().unwrap().contains(&opid));
        state.update_op(opid, false).unwrap();
        assert!(state.invalid_ops().unwrap().contains(&opid));
        assert_eq!(state.invalid_ops().unwrap().release(), bset![opid]);
        state.update_op(opid, true).unwrap();
        assert!(!state.invalid_ops().unwrap().contains(&opid));
    }

    #[test]
    fn sqlite_stock_opens() {
        let stock = open_in_memory().unwrap();
        assert_eq!(stock.as_stash_provider().schemata().count(), 0);
    }

    #[test]
    fn keyset_cursor_iterates_lazily_and_completely() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (k BLOB PRIMARY KEY, v BLOB NOT NULL)")
            .unwrap();
        // More than two batches, ensuring pagination is exercised
        let count = BATCH_SIZE * 2 + 7;
        for i in 0..count {
            let key = (i as u32).to_be_bytes().to_vec();
            conn.execute("INSERT INTO t (k, v) VALUES (?1, ?2)", (&key, &key))
                .unwrap();
        }
        let db = Arc::new(Mutex::new(Db { conn, in_tx: false }));
        fn map_raw(row: &Row<'_>) -> Result<(Value, Vec<u8>), SqlError> {
            let key: Vec<u8> = row.get(0).map_err(SqlError::from)?;
            Ok((Value::Blob(key.clone()), key))
        }
        let cursor = SqlKeyCursor::new(
            db,
            format!("SELECT k, v FROM t WHERE k > ?1 ORDER BY k LIMIT {BATCH_SIZE}"),
            vec![],
            map_raw,
        );
        let items = cursor.collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(items.len(), count);
        let expected = (0..count)
            .map(|i| (i as u32).to_be_bytes().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(items, expected);
    }
}
