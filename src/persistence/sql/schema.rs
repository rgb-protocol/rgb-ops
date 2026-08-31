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

use super::SqlError;

/// Current database schema version, stored in `PRAGMA user_version`.
const VERSION: i64 = 1;

/// All ids are fixed-width strict-encoded blobs; all values are strict-encoded
/// blobs. Columns are split out only when SQL filters on them ("column if SQL
/// filters on it, blob if Rust decodes it").
const DDL: &str = "
-- Stash ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema (
    schema_id   BLOB NOT NULL PRIMARY KEY,
    data        BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS genesis (
    contract_id BLOB NOT NULL PRIMARY KEY,
    schema_id   BLOB NOT NULL,
    data        BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS bundle (
    bundle_id   BLOB NOT NULL PRIMARY KEY,
    data        BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS witness (
    txid        BLOB NOT NULL PRIMARY KEY,
    data        BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS lib (
    lib_id      BLOB NOT NULL PRIMARY KEY,
    data        BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS type_system (
    row_id      INTEGER NOT NULL PRIMARY KEY CHECK (row_id = 0),
    data        BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS secret_seal (
    secret      BLOB NOT NULL PRIMARY KEY,
    seal_data   BLOB NOT NULL
);
-- Derived from witnesses with tapret DBC proofs, maintained by
-- replace_witness so that taprets() is a plain scan
CREATE TABLE IF NOT EXISTS tapret (
    txid        BLOB NOT NULL PRIMARY KEY,
    commitment  BLOB NOT NULL
);

-- State ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS witness_ord (
    txid        BLOB NOT NULL PRIMARY KEY,
    ord         BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS invalid_op (
    op_id       BLOB NOT NULL PRIMARY KEY
);
-- Per-contract metadata: schema and per-type global state limits.
CREATE TABLE IF NOT EXISTS contract_meta (
    contract_id BLOB NOT NULL PRIMARY KEY,
    schema_id   BLOB NOT NULL,
    limits_blob BLOB NOT NULL   -- strict-encoded TinyOrdMap<GlobalStateType, u24>
);
-- One row per global state entry (one per (contract, type, op, index)).
CREATE TABLE IF NOT EXISTS global_state (
    id          INTEGER PRIMARY KEY,
    contract_id BLOB    NOT NULL,
    type_id     INTEGER NOT NULL,
    out_blob    BLOB    NOT NULL,  -- strict-encoded GlobalOut
    value_blob  BLOB    NOT NULL,  -- strict-encoded RevealedData
    UNIQUE (contract_id, type_id, out_blob)
);
CREATE INDEX IF NOT EXISTS idx_global_state ON global_state (contract_id, type_id);
-- One row per revealed assignment (fungible / structured / declarative).
-- state_type: 'F' = fungible, 'D' = data (structured), 'R' = rights (declarative)
CREATE TABLE IF NOT EXISTS assignment (
    id           INTEGER PRIMARY KEY,
    contract_id  BLOB    NOT NULL,
    state_type   TEXT    NOT NULL CHECK (state_type IN ('F', 'D', 'R')),
    type_id      INTEGER NOT NULL,
    op_id        BLOB    NOT NULL,
    output_no    INTEGER NOT NULL,
    seal_txid    BLOB    NOT NULL,
    seal_vout    INTEGER NOT NULL,
    witness_txid BLOB,              -- NULL = genesis (no witness)
    bundle_id    BLOB,              -- NULL = genesis (no bundle)
    value_blob   BLOB    NOT NULL,  -- strict-encoded state; empty blob for rights
    UNIQUE (contract_id, op_id, type_id, output_no, seal_txid, seal_vout)
);
CREATE INDEX IF NOT EXISTS idx_assignment ON assignment (contract_id, state_type, type_id, \
                   seal_txid, seal_vout);

-- Index ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS registered_contract (
    contract_id BLOB NOT NULL PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS bundle_contract (
    bundle_id   BLOB NOT NULL PRIMARY KEY,
    contract_id BLOB NOT NULL
);
-- A bundle can gain witnesses over time
CREATE TABLE IF NOT EXISTS bundle_witness (
    bundle_id   BLOB NOT NULL,
    witness_id  BLOB NOT NULL,
    PRIMARY KEY (bundle_id, witness_id)
);
CREATE TABLE IF NOT EXISTS op_bundle (
    op_id       BLOB NOT NULL PRIMARY KEY,
    bundle_id   BLOB NOT NULL
);
-- The outputs of one operation can be spent by many bundles
CREATE TABLE IF NOT EXISTS op_bundle_child (
    op_id       BLOB NOT NULL,
    bundle_id   BLOB NOT NULL,
    PRIMARY KEY (op_id, bundle_id)
);
-- One row per (outpoint, opout) pair, covering both genesis and transition
-- assignments
CREATE TABLE IF NOT EXISTS outpoint_opout (
    contract_id BLOB NOT NULL REFERENCES registered_contract (contract_id),
    txid        BLOB NOT NULL,
    vout        INTEGER NOT NULL,
    opout       BLOB NOT NULL,
    PRIMARY KEY (contract_id, txid, vout, opout)
);
CREATE INDEX IF NOT EXISTS idx_outpoint_opout_outpoint
    ON outpoint_opout (txid, vout);
-- From confidential-seal assignments
CREATE TABLE IF NOT EXISTS terminal (
    secret_seal BLOB NOT NULL,
    opout       BLOB NOT NULL,
    PRIMARY KEY (secret_seal, opout)
);
";

pub(super) fn migrate(conn: &Connection) -> Result<(), SqlError> {
    conn.execute_batch("PRAGMA foreign_keys = ON")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    match version {
        0 => {
            conn.execute_batch(DDL)?;
            conn.execute_batch(&format!("PRAGMA user_version = {VERSION}"))?;
            Ok(())
        }
        VERSION => Ok(()),
        unsupported => Err(SqlError(format!(
            "unsupported database schema version {unsupported}; this library supports version \
             {VERSION}"
        ))),
    }
}
