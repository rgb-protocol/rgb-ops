// RGB ops library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 RGB-Tools. All rights reserved.
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

use aluvm::library::{Lib, LibId};
use rgb::commit_verify::{CommitId, Conceal};
use rgb::dbc::tapret::TapretCommitment;
use rgb::validation::DbcProof;
use rgb::{
    BundleId, ContractId, Genesis, GraphSeal, Operation, Schema, SchemaId, TransitionBundle, Txid,
};
use strict_encoding::{StrictDecode, StrictEncode};
use strict_types::TypeSystem;

use super::{dec, enc, lock, map_decode, SharedDb, SqlError, SqlKeyCursor, BATCH_SIZE};
use crate::containers::SealWitness;
use crate::persistence::{
    StashInconsistency, StashProvider, StashProviderError, StashReadProvider, StashWriteProvider,
};
use crate::SecretSeal;

/// SQLite-backed implementation of the stash provider.
#[derive(Clone, Debug)]
pub struct SqlStash {
    db: SharedDb,
}

impl SqlStash {
    pub(super) fn new(db: SharedDb) -> Self { Self { db } }

    /// Keyed single-row lookup decoding the value blob; `None` when the key
    /// is absent.
    fn keyed<T: StrictDecode>(
        &self,
        sql: &str,
        key: &impl StrictEncode,
    ) -> Result<Option<T>, SqlError> {
        let key = enc(key)?;
        lock(&self.db)?
            .blob(sql, &key)?
            .map(|blob| dec(&blob))
            .transpose()
    }

    /// Like [`Self::keyed`], but with the error pre-wrapped for the provider
    /// methods returning [`StashProviderError`].
    fn keyed_provider<T: StrictDecode>(
        &self,
        sql: &str,
        key: &impl StrictEncode,
    ) -> Result<Option<T>, StashProviderError<SqlError>> {
        self.keyed(sql, key)
            .map_err(StashProviderError::Connectivity)
    }
}

impl StashProvider for SqlStash {}

impl StashReadProvider for SqlStash {
    type Error = SqlError;

    fn type_system(&self) -> Result<TypeSystem, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT data FROM type_system WHERE row_id = 0")?;
        match stmt.query_row([], |row| row.get::<_, Vec<u8>>(0)) {
            Ok(blob) => dec(&blob),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(TypeSystem::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn lib(&self, id: LibId) -> Result<Lib, StashProviderError<Self::Error>> {
        self.keyed_provider("SELECT data FROM lib WHERE lib_id = ?1", &id)?
            .ok_or_else(|| StashInconsistency::LibAbsent(id).into())
    }

    fn schemata(&self) -> impl Iterator<Item = Result<Schema, Self::Error>> + '_ {
        SqlKeyCursor::new(
            self.db.clone(),
            format!(
                "SELECT schema_id, data FROM schema WHERE schema_id > ?1 ORDER BY schema_id LIMIT \
                 {BATCH_SIZE}"
            ),
            vec![],
            map_decode::<Schema>,
        )
    }

    fn schema(&self, schema_id: SchemaId) -> Result<Schema, StashProviderError<Self::Error>> {
        self.keyed_provider("SELECT data FROM schema WHERE schema_id = ?1", &schema_id)?
            .ok_or_else(|| StashInconsistency::SchemaAbsent(schema_id).into())
    }

    fn geneses(&self) -> impl Iterator<Item = Result<Genesis, Self::Error>> + '_ {
        SqlKeyCursor::new(
            self.db.clone(),
            format!(
                "SELECT contract_id, data FROM genesis WHERE contract_id > ?1 ORDER BY \
                 contract_id LIMIT {BATCH_SIZE}"
            ),
            vec![],
            map_decode::<Genesis>,
        )
    }

    fn genesis(&self, contract_id: ContractId) -> Result<Genesis, StashProviderError<Self::Error>> {
        self.keyed_provider("SELECT data FROM genesis WHERE contract_id = ?1", &contract_id)?
            .ok_or_else(|| StashInconsistency::ContractAbsent(contract_id).into())
    }

    fn contract_schema(
        &self,
        contract_id: ContractId,
    ) -> Result<Schema, StashProviderError<Self::Error>> {
        // Single round-trip: join the contract's genesis to its schema.
        self.keyed_provider(
            "SELECT s.data FROM schema s JOIN genesis g ON s.schema_id = g.schema_id WHERE \
             g.contract_id = ?1",
            &contract_id,
        )?
        .ok_or_else(|| StashInconsistency::ContractAbsent(contract_id).into())
    }

    fn bundle_ids(&self) -> Result<impl Iterator<Item = BundleId>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached("SELECT bundle_id FROM bundle")?;
        let ids = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .map(|blob| dec(&blob?))
            .collect::<Result<Vec<BundleId>, SqlError>>()?;
        Ok(ids.into_iter())
    }

    fn bundle(
        &self,
        bundle_id: BundleId,
    ) -> Result<TransitionBundle, StashProviderError<Self::Error>> {
        self.keyed_provider("SELECT data FROM bundle WHERE bundle_id = ?1", &bundle_id)?
            .ok_or_else(|| StashInconsistency::BundleAbsent(bundle_id).into())
    }

    fn witness_ids(&self) -> Result<impl Iterator<Item = Txid>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached("SELECT txid FROM witness")?;
        let ids = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .map(|blob| dec(&blob?))
            .collect::<Result<Vec<Txid>, SqlError>>()?;
        Ok(ids.into_iter())
    }

    fn witness(&self, witness_id: Txid) -> Result<SealWitness, StashProviderError<Self::Error>> {
        self.keyed_provider("SELECT data FROM witness WHERE txid = ?1", &witness_id)?
            .ok_or_else(|| StashInconsistency::WitnessAbsent(witness_id).into())
    }

    /// Reads the tapret table, which [`StashWriteProvider::replace_witness`]
    /// keeps in sync with the tapret-committed witnesses, so this is a plain
    /// scan rather than a decode of every stored witness.
    fn taprets(&self) -> Result<impl Iterator<Item = (Txid, TapretCommitment)>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT txid, commitment FROM tapret")?;
        let taprets = stmt
            .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))?
            .map(|res| {
                let (txid, commitment) = res?;
                Ok((dec(&txid)?, dec(&commitment)?))
            })
            .collect::<Result<Vec<(Txid, TapretCommitment)>, SqlError>>()?;
        Ok(taprets.into_iter())
    }

    fn seal_secret(&self, secret: SecretSeal) -> Result<Option<GraphSeal>, Self::Error> {
        self.keyed("SELECT seal_data FROM secret_seal WHERE secret = ?1", &secret)
    }

    fn secret_seals(&self) -> Result<impl Iterator<Item = GraphSeal>, Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT seal_data FROM secret_seal")?;
        let seals = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .map(|blob| dec(&blob?))
            .collect::<Result<Vec<GraphSeal>, SqlError>>()?;
        Ok(seals.into_iter())
    }
}

impl StashWriteProvider for SqlStash {
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

    fn replace_schema(&mut self, schema: Schema) -> Result<bool, Self::Error> {
        // Following the in-memory provider, schemas are insert-if-absent
        let n = lock(&self.db)?.conn.execute(
            "INSERT OR IGNORE INTO schema (schema_id, data) VALUES (?1, ?2)",
            (enc(&schema.schema_id())?, enc(&schema)?),
        )?;
        Ok(n > 0)
    }

    fn replace_genesis(&mut self, genesis: Genesis) -> Result<bool, Self::Error> {
        let contract_id = enc(&genesis.contract_id())?;
        let db = lock(&self.db)?;
        let present = db.exists("SELECT 1 FROM genesis WHERE contract_id = ?1", &contract_id)?;
        db.conn.execute(
            "INSERT OR REPLACE INTO genesis (contract_id, schema_id, data) VALUES (?1, ?2, ?3)",
            (contract_id, enc(&genesis.schema_id)?, enc(&genesis)?),
        )?;
        Ok(!present)
    }

    fn replace_bundle(&mut self, bundle: TransitionBundle) -> Result<bool, Self::Error> {
        let bundle_id = enc(&bundle.bundle_id())?;
        let db = lock(&self.db)?;
        let present = db.exists("SELECT 1 FROM bundle WHERE bundle_id = ?1", &bundle_id)?;
        db.conn.execute(
            "INSERT OR REPLACE INTO bundle (bundle_id, data) VALUES (?1, ?2)",
            (bundle_id, enc(&bundle)?),
        )?;
        Ok(!present)
    }

    fn replace_witness(&mut self, witness: SealWitness) -> Result<bool, Self::Error> {
        let txid = enc(&witness.witness_id())?;
        let db = lock(&self.db)?;
        let present = db.exists("SELECT 1 FROM witness WHERE txid = ?1", &txid)?;
        db.conn.execute(
            "INSERT OR REPLACE INTO witness (txid, data) VALUES (?1, ?2)",
            (&txid, enc(&witness)?),
        )?;
        // Keep the derived tapret table in sync so that `taprets()` reads are
        // a plain scan
        match &witness.dbc_proof {
            DbcProof::Tapret(tapret) => {
                let commitment = TapretCommitment {
                    mpc: witness.merkle_block.commit_id(),
                    nonce: tapret.path_proof.nonce(),
                };
                db.conn.execute(
                    "INSERT OR REPLACE INTO tapret (txid, commitment) VALUES (?1, ?2)",
                    (&txid, enc(&commitment)?),
                )?;
            }
            _ => {
                db.conn
                    .execute("DELETE FROM tapret WHERE txid = ?1", (&txid,))?;
            }
        }
        Ok(!present)
    }

    fn replace_lib(&mut self, lib: Lib) -> Result<bool, Self::Error> {
        let lib_id = enc(&lib.id())?;
        let db = lock(&self.db)?;
        let present = db.exists("SELECT 1 FROM lib WHERE lib_id = ?1", &lib_id)?;
        db.conn.execute(
            "INSERT OR REPLACE INTO lib (lib_id, data) VALUES (?1, ?2)",
            (lib_id, enc(&lib)?),
        )?;
        Ok(!present)
    }

    fn consume_types(&mut self, types: TypeSystem) -> Result<(), Self::Error> {
        let db = lock(&self.db)?;
        let mut stmt = db
            .conn
            .prepare_cached("SELECT data FROM type_system WHERE row_id = 0")?;
        let mut existing = match stmt.query_row([], |row| row.get::<_, Vec<u8>>(0)) {
            Ok(blob) => dec::<TypeSystem>(&blob)?,
            Err(rusqlite::Error::QueryReturnedNoRows) => TypeSystem::default(),
            Err(e) => return Err(e.into()),
        };
        existing
            .extend(types)
            .map_err(|e| SqlError(e.to_string()))?;
        db.conn.execute(
            "INSERT OR REPLACE INTO type_system (row_id, data) VALUES (0, ?1)",
            (enc(&existing)?,),
        )?;
        Ok(())
    }

    fn add_secret_seal(&mut self, seal: GraphSeal) -> Result<bool, Self::Error> {
        let n = lock(&self.db)?.conn.execute(
            "INSERT OR IGNORE INTO secret_seal (secret, seal_data) VALUES (?1, ?2)",
            (enc(&seal.conceal())?, enc(&seal)?),
        )?;
        Ok(n > 0)
    }
}
