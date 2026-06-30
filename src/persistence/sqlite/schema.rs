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

use rusqlite::Connection;

use super::SqliteError;

/// Current database schema version, stored in `PRAGMA user_version`.
const VERSION: i64 = 1;

/// All ids are fixed-width strict-encoded blobs; all values are strict-encoded
/// blobs. A field earns a column of its own when SQL has to filter or join on
/// it, or when it is read or written without the rest of the record it belongs
/// to ("column if SQL filters on it, blob if Rust decodes it as a whole").
///
/// Where a column and a blob would hold the same fact, the column wins and the
/// blob does not carry it, so the two can never disagree. The exception is the
/// key of a store record, which is derived from the record itself - a schema
/// id, a contract id, a bundle id, a witness txid, a library id, a seal
/// concealment. That duplication is unavoidable, since the key has to be
/// indexable, and it is checked on every read: see `dec_keyed` in the parent
/// module. Nothing is stored whose key cannot be recomputed that way.
const DDL: &str = "
CREATE TABLE IF NOT EXISTS schema (
    schema_id   BLOB NOT NULL PRIMARY KEY,
    schema_blob BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS genesis (
    contract_id  BLOB NOT NULL PRIMARY KEY,
    schema_id    BLOB NOT NULL
                 REFERENCES schema (schema_id) DEFERRABLE INITIALLY DEFERRED,
    genesis_blob BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS bundle (
    bundle_id   BLOB NOT NULL PRIMARY KEY,
    bundle_blob BLOB NOT NULL
);

-- The four parts of a SealWitness are stored side by side rather than as one
-- blob, so that each can be read and written on its own.
CREATE TABLE IF NOT EXISTS witness (
    txid                  BLOB NOT NULL PRIMARY KEY,
    tx_blob               BLOB NOT NULL,
    mpc_merkle_block_blob BLOB NOT NULL,
    dbc_proof_blob        BLOB NOT NULL,
    spv_proof_blob        BLOB            -- NULL = no SPV proof known
);

CREATE TABLE IF NOT EXISTS aluvm_lib (
    aluvm_lib_id   BLOB NOT NULL PRIMARY KEY,
    aluvm_lib_blob BLOB NOT NULL
);

-- Storing TypeLib instead of TypeSystem so that semantic ids can be recomputed
CREATE TABLE IF NOT EXISTS type_lib (
    type_lib_id   BLOB NOT NULL PRIMARY KEY,
    type_lib_blob BLOB NOT NULL
);

-- Which libraries a schema was defined by. Unlike the AluVM libraries, which
-- are reachable from the schema itself through its entry points and their call
-- closure, this cannot be derived: a schema commits to semantic ids, not to the
-- libraries defining them. So the link a schema definition carried is kept,
-- many-to-many since libraries are shared between schemata.
CREATE TABLE IF NOT EXISTS schema_type_lib (
    schema_id   BLOB NOT NULL
                REFERENCES schema (schema_id) DEFERRABLE INITIALLY DEFERRED,
    type_lib_id BLOB NOT NULL
                REFERENCES type_lib (type_lib_id) DEFERRABLE INITIALLY DEFERRED,
    PRIMARY KEY (schema_id, type_lib_id)
);

CREATE TABLE IF NOT EXISTS secret_seal (
    secret_seal     BLOB NOT NULL PRIMARY KEY,
    graph_seal_blob BLOB NOT NULL
);

-- Foreign keys below tie derived rows to the tables that are their source of
-- truth. All are DEFERRABLE INITIALLY DEFERRED: a whole consignment persists
-- inside one transaction, so integrity is enforced at COMMIT, not per statement.
-- WitnessOrd fully decomposed into columns: it is the most filtered-on value in
-- the store (every allocation and global-state read asks whether a witness is
-- archived, and witness refresh asks for a height range), so it is a blob
-- nowhere. `status` mirrors the enum's strict-encoding tag order; the three
-- position columns are set together, and only for a mined witness.
CREATE TABLE IF NOT EXISTS witness_ord (
    txid        BLOB NOT NULL PRIMARY KEY
                REFERENCES witness (txid) DEFERRABLE INITIALLY DEFERRED,
    status      INTEGER NOT NULL,  -- 0 mined, 1 tentative, 2 ignored, 3 archived
    height      INTEGER,           -- mined only, >= 1
    timestamp   INTEGER,           -- mined only
    layer1      INTEGER,           -- mined only, 0 bitcoin / 1 liquid
    CHECK (((status = 0) = (height IS NOT NULL))
       AND ((status = 0) = (timestamp IS NOT NULL))
       AND ((status = 0) = (layer1 IS NOT NULL)))
);

-- Allow faster selects on status and height.
CREATE INDEX IF NOT EXISTS idx_witness_ord_status ON witness_ord (status, height);

CREATE TABLE IF NOT EXISTS invalid_op (
    opid        BLOB NOT NULL PRIMARY KEY
);

-- One row per global state entry (one per (contract, type, op, index)).
-- The entry is tied to the bundle which produced it, never to one witness: a
-- bundle may be anchored by several (an RBF replaces the transaction, both may
-- be on file), and which of them is valid changes over time. Storing one of
-- them here would be a copy of a set that keeps growing, and the copy is what
-- goes stale - so validity is decided against `bundle_witness` at read time,
-- and the witness an entry is reported under is resolved there too.
CREATE TABLE IF NOT EXISTS global_state (
    global_state_id INTEGER PRIMARY KEY,
    contract_id     BLOB    NOT NULL
                    REFERENCES genesis (contract_id) DEFERRABLE INITIALLY DEFERRED,
    type_id         INTEGER NOT NULL,
    opid            BLOB    NOT NULL,
    out_index       INTEGER NOT NULL,
    nonce           INTEGER NOT NULL,
    bundle_id       BLOB,             -- NULL = genesis (no bundle)
    transition_type INTEGER,          -- NULL = genesis; set with bundle_id
    value_blob      BLOB    NOT NULL, -- strict-encoded RevealedData
    UNIQUE (contract_id, type_id, opid, out_index),
    CHECK ((bundle_id IS NULL) = (transition_type IS NULL))
);

-- One row per revealed assignment.
-- state_type: 'F' = fungible, 'S' = structured, 'R' = rights (declarative)
-- `bundle_id` and not a witness, for the reason given above `global_state`: the
-- bundle an operation belongs to never changes, the set of witnesses anchoring
-- that bundle does.
CREATE TABLE IF NOT EXISTS assignment (
    assignment_id INTEGER PRIMARY KEY,
    contract_id   BLOB    NOT NULL
                  REFERENCES genesis (contract_id) DEFERRABLE INITIALLY DEFERRED,
    state_type    TEXT    NOT NULL CHECK (state_type IN ('F', 'S', 'R')),
    type_id       INTEGER NOT NULL,
    opid          BLOB    NOT NULL,
    output_no     INTEGER NOT NULL,
    -- the seal as defined, not as resolved: NULL = on the witness transaction,
    -- landing on seal_vout of every witness `bundle_witness` holds for bundle_id
    seal_txid     BLOB,
    seal_vout     INTEGER NOT NULL,
    bundle_id     BLOB,              -- NULL = genesis (no bundle)
    value_blob    BLOB    NOT NULL,  -- strict-encoded state; empty blob for rights
    -- the opout, and not the seal with it: an assignment has exactly one seal
    -- definition. A seal on the witness transaction resolves to a different
    -- outpoint under each witness of its bundle (an RBF, or every commitment
    -- transaction of a Lightning channel carrying the bundle), and all of them
    -- stay resolvable through `bundle_witness` rather than one per row
    UNIQUE (contract_id, opid, type_id, output_no),
    -- genesis has no witness to resolve against
    CHECK (seal_txid IS NOT NULL OR bundle_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_assignment ON assignment (contract_id, state_type, type_id, \
                   seal_txid, seal_vout);

-- Allow faster selects on contract_id + seal_txid + seal_vout.
CREATE INDEX IF NOT EXISTS idx_assignment_seal
    ON assignment (contract_id, seal_txid, seal_vout);

-- Allow faster selects on seal_txid + seal_vout.
CREATE INDEX IF NOT EXISTS idx_assignment_seal_any
    ON assignment (seal_txid, seal_vout);

-- Allow faster selects of the seals on a witness transaction, reached from the
-- witness through `bundle_witness`. Not unique: one bundle may assign several
-- states to the same output.
CREATE INDEX IF NOT EXISTS idx_assignment_witness_seal
    ON assignment (bundle_id, seal_vout) WHERE seal_txid IS NULL;

CREATE TABLE IF NOT EXISTS bundle_contract (
    bundle_id   BLOB NOT NULL PRIMARY KEY
                REFERENCES bundle (bundle_id) DEFERRABLE INITIALLY DEFERRED,
    contract_id BLOB NOT NULL
                REFERENCES genesis (contract_id) DEFERRABLE INITIALLY DEFERRED
);

-- A bundle can gain witnesses over time
CREATE TABLE IF NOT EXISTS bundle_witness (
    bundle_id   BLOB NOT NULL
                REFERENCES bundle (bundle_id) DEFERRABLE INITIALLY DEFERRED,
    txid        BLOB NOT NULL
                REFERENCES witness (txid) DEFERRABLE INITIALLY DEFERRED,
    PRIMARY KEY (bundle_id, txid)
);

-- Reverse direction: the bundles a witness anchors, which a reorg crossing a
-- witness in or out of validity asks for. The merkle block inside the witness
-- record holds the same answer, but reading it there means decoding the whole
-- witness.
CREATE INDEX IF NOT EXISTS idx_bundle_witness_txid ON bundle_witness (txid);

CREATE TABLE IF NOT EXISTS op_bundle (
    opid        BLOB NOT NULL PRIMARY KEY,
    bundle_id   BLOB NOT NULL
                REFERENCES bundle (bundle_id) DEFERRABLE INITIALLY DEFERRED
);

-- Reverse direction: the operations of a bundle, which the reorg walks ask for
-- per bundle. Without it the only answer is decoding the whole bundle blob.
CREATE INDEX IF NOT EXISTS idx_op_bundle_bundle ON op_bundle (bundle_id);

-- One row per (spent opout, spender): which (opid, type_id, output_no) is
-- consumed, by which spending transition (child_opid), inside which child
-- bundle. Single-use seals make a second spend of one opout invalid, not
-- unrepresentable: until a reorg settles which of two candidate spends stands,
-- the store holds both, and both must be reachable from the operation they
-- spend from - invalidation and revalidation walk the graph through this table.
-- Hence child_opid in the key: without it the second spender is dropped, and
-- its whole subtree with it.
CREATE TABLE IF NOT EXISTS op_input (
    opid            BLOB    NOT NULL, -- parent op (producer of the spent opout)
    type_id         INTEGER NOT NULL, -- assignment type of the spent opout
    output_no       INTEGER NOT NULL, -- output index of the spent opout
    child_opid      BLOB    NOT NULL, -- the spending transition
    child_bundle_id BLOB    NOT NULL  -- child bundle that spends it
                    REFERENCES bundle (bundle_id) DEFERRABLE INITIALLY DEFERRED,
    PRIMARY KEY (opid, type_id, output_no, child_opid)
);

-- Backward discovery: all opouts a transition spends.
CREATE INDEX IF NOT EXISTS idx_op_input_child_opid ON op_input (child_opid);

-- One row per (outpoint, opout) pair, covering both genesis and transition
-- assignments.
CREATE TABLE IF NOT EXISTS outpoint_opout (
    contract_id BLOB NOT NULL
                REFERENCES genesis (contract_id) DEFERRABLE INITIALLY DEFERRED,
    txid        BLOB NOT NULL,
    vout        INTEGER NOT NULL,
    opout       BLOB NOT NULL,
    PRIMARY KEY (contract_id, txid, vout, opout)
);

CREATE INDEX IF NOT EXISTS idx_outpoint_opout_outpoint
    ON outpoint_opout (txid, vout);

-- Blinded seals, indexed by concealment: the same opout map as outpoint_opout,
-- for seals that have not been revealed as an outpoint yet.
CREATE TABLE IF NOT EXISTS secret_seal_opout (
    contract_id BLOB NOT NULL
                REFERENCES genesis (contract_id) DEFERRABLE INITIALLY DEFERRED,
    secret_seal BLOB NOT NULL,
    opout       BLOB NOT NULL,
    PRIMARY KEY (contract_id, secret_seal, opout)
);
";

pub(super) fn migrate(conn: &Connection) -> Result<(), SqliteError> {
    // SQLite leaves foreign keys off by default: without this, REFERENCES are
    // documentation only and no check is ever done. A connection pragma, so it
    // is set here on every open, not once in the DDL.
    conn.execute_batch("PRAGMA foreign_keys = ON")?;
    // The journal mode is deliberately not set here: it is a persistent
    // property of the database file and a deployment choice - WAL trades
    // side files and a local-filesystem requirement for readers not waiting
    // on the writer's commits - so it is the application's to make, on the
    // database file, not the library's to impose from a migration.
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    match version {
        0 => {
            conn.execute_batch(DDL)?;
            conn.execute_batch(&format!("PRAGMA user_version = {VERSION}"))?;
            Ok(())
        }
        VERSION => Ok(()),
        unsupported => Err(SqliteError::Storage(format!(
            "unsupported database schema version {unsupported}; this library supports version \
             {VERSION}"
        ))),
    }
}
