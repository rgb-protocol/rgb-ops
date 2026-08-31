// RGB ops library for working with smart contracts on Bitcoin & Lightning
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

use std::collections::BTreeSet;
use std::fmt::Write;

use amplify::confinement::{Confined, SmallOrdSet};
use rgb::bitcoin::{OutPoint as Outpoint, Txid};
use rgb::{
    Assign, AssignmentType, BuilderSeal, BundleId, ContractId, ExposedSeal, ExposedState,
    GenesisSeal, GraphSeal, OpId, Opout,
};
use rusqlite::params_from_iter;
use rusqlite::types::Value;

use super::{dec, enc, lock, map_decode, SharedDb, SqlError, SqlKeyCursor, BATCH_SIZE};
use crate::persistence::{
    IndexInconsistency, IndexProvider, IndexReadError, IndexReadProvider, IndexWriteError,
    IndexWriteProvider,
};
use crate::SecretSeal;

/// Builds a `(?N,?N+1),(?N+2,?N+3),…` row-value list for binding outpoint
/// pairs, starting at placeholder index `first`.
fn outpoint_values(first: usize, count: usize) -> String {
    let mut s = String::new();
    for i in 0..count {
        if i > 0 {
            s.push(',');
        }
        let txid = first + i * 2;
        let vout = txid + 1;
        write!(s, "(?{txid},?{vout})").expect("writing to string never fails");
    }
    s
}

/// Builds a `?N,?N+1,…` placeholder list starting at index `first`.
fn placeholders(first: usize, count: usize) -> String {
    let mut s = String::new();
    for i in 0..count {
        if i > 0 {
            s.push(',');
        }
        write!(s, "?{}", first + i).expect("writing to string never fails");
    }
    s
}

/// SQLite-backed implementation of the index provider.
#[derive(Clone, Debug)]
pub struct SqlIndex {
    db: SharedDb,
}

impl SqlIndex {
    pub(super) fn new(db: SharedDb) -> Self { Self { db } }

    fn contract_registered(&self, contract_id: ContractId) -> Result<bool, SqlError> {
        let key = enc(&contract_id)?;
        lock(&self.db)?.exists("SELECT 1 FROM registered_contract WHERE contract_id = ?1", &key)
    }
}

impl IndexProvider for SqlIndex {}

impl IndexReadProvider for SqlIndex {
    type Error = SqlError;

    fn contracts_assigning(
        &self,
        outputs: BTreeSet<Outpoint>,
    ) -> Result<BTreeSet<ContractId>, Self::Error> {
        if outputs.is_empty() {
            return Ok(BTreeSet::new());
        }
        let mut params = Vec::with_capacity(outputs.len() * 2);
        for outpoint in &outputs {
            params.push(Value::Blob(enc(&outpoint.txid)?));
            params.push(Value::Integer(i64::from(outpoint.vout)));
        }
        let values = outpoint_values(2, outputs.len());
        let sql = format!(
            "SELECT DISTINCT contract_id, contract_id FROM outpoint_opout WHERE contract_id > ?1 \
             AND (txid, vout) IN (VALUES {values}) ORDER BY contract_id LIMIT {BATCH_SIZE}"
        );
        let cursor = SqlKeyCursor::new(self.db.clone(), sql, params, map_decode::<ContractId>);
        // Eagerly collect so decode errors on any batch surface in the `Result`
        // instead of being silently dropped.
        cursor.collect()
    }

    fn public_opouts(
        &self,
        contract_id: ContractId,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>> {
        if !self
            .contract_registered(contract_id)
            .map_err(IndexReadError::Connectivity)?
        {
            return Err(IndexInconsistency::ContractAbsent(contract_id).into());
        }
        // Nothing populates public opouts (matching the in-memory provider,
        // where the `ContractIndex.public_opouts` set has no writer)
        Ok(BTreeSet::new())
    }

    fn opouts_by_outputs(
        &self,
        contract_id: ContractId,
        outputs: impl IntoIterator<Item = impl Into<Outpoint>>,
    ) -> Result<BTreeSet<Opout>, IndexReadError<Self::Error>> {
        if !self
            .contract_registered(contract_id)
            .map_err(IndexReadError::Connectivity)?
        {
            return Err(IndexInconsistency::ContractAbsent(contract_id).into());
        }
        let outputs: Vec<Outpoint> = outputs.into_iter().map(Into::into).collect();
        if outputs.is_empty() {
            return Ok(BTreeSet::new());
        }
        // A single query; missing outpoints are detected client-side by
        // diffing the outpoints seen in the result against the request
        let (opouts, seen) = (|| {
            let mut params: Vec<Value> = Vec::with_capacity(outputs.len() * 2 + 1);
            params.push(Value::Blob(enc(&contract_id)?));
            for outpoint in &outputs {
                params.push(Value::Blob(enc(&outpoint.txid)?));
                params.push(Value::Integer(i64::from(outpoint.vout)));
            }
            let values = outpoint_values(2, outputs.len());
            let sql = format!(
                "SELECT txid, vout, opout FROM outpoint_opout WHERE contract_id = ?1 AND (txid, \
                 vout) IN (VALUES {values})"
            );
            let db = lock(&self.db)?;
            let mut stmt = db.conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(params.iter()))?;
            let mut opouts = BTreeSet::new();
            let mut seen = BTreeSet::<(Vec<u8>, i64)>::new();
            loop {
                let Some(row) = rows.next()? else { break };
                let txid: Vec<u8> = row.get(0)?;
                let vout: i64 = row.get(1)?;
                let opout: Vec<u8> = row.get(2)?;
                opouts.insert(dec::<Opout>(&opout)?);
                seen.insert((txid, vout));
            }
            Ok::<_, SqlError>((opouts, seen))
        })()
        .map_err(IndexReadError::Connectivity)?;
        for outpoint in outputs {
            let key = (
                enc(&outpoint.txid).map_err(IndexReadError::Connectivity)?,
                i64::from(outpoint.vout),
            );
            if !seen.contains(&key) {
                return Err(IndexInconsistency::OutpointUnknown(outpoint, contract_id).into());
            }
        }
        Ok(opouts)
    }

    fn opouts_by_terminals(
        &self,
        terminals: impl IntoIterator<Item = SecretSeal>,
    ) -> Result<BTreeSet<Opout>, Self::Error> {
        let terminals: Vec<SecretSeal> = terminals.into_iter().collect();
        if terminals.is_empty() {
            return Ok(BTreeSet::new());
        }
        let params = terminals
            .iter()
            .map(|seal| Ok(Value::Blob(enc(seal)?)))
            .collect::<Result<Vec<_>, SqlError>>()?;
        let sql = format!(
            "SELECT opout FROM terminal WHERE secret_seal IN ({})",
            placeholders(1, terminals.len())
        );
        let db = lock(&self.db)?;
        let mut stmt = db.conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params_from_iter(params.iter()))?;
        let mut opouts = BTreeSet::new();
        loop {
            let Some(row) = rows.next()? else { break };
            let opout: Vec<u8> = row.get(0)?;
            opouts.insert(dec::<Opout>(&opout)?);
        }
        Ok(opouts)
    }

    fn bundle_id_for_op(&self, opid: OpId) -> Result<BundleId, IndexReadError<Self::Error>> {
        let blob = (|| {
            let key = enc(&opid)?;
            lock(&self.db)?.blob("SELECT bundle_id FROM op_bundle WHERE op_id = ?1", &key)
        })()
        .map_err(IndexReadError::Connectivity)?;
        match blob {
            Some(blob) => dec(&blob).map_err(IndexReadError::Connectivity),
            None => Err(IndexInconsistency::BundleAbsent(opid).into()),
        }
    }

    fn bundle_ids_children_of_op(
        &self,
        opid: OpId,
    ) -> Result<SmallOrdSet<BundleId>, IndexReadError<Self::Error>> {
        let children = (|| {
            let key = enc(&opid)?;
            let db = lock(&self.db)?;
            let mut stmt = db
                .conn
                .prepare_cached("SELECT bundle_id FROM op_bundle_child WHERE op_id = ?1")?;
            let mut rows = stmt.query([key])?;
            let mut children = BTreeSet::new();
            loop {
                let Some(row) = rows.next()? else { break };
                let bundle_id: Vec<u8> = row.get(0)?;
                children.insert(dec::<BundleId>(&bundle_id)?);
            }
            Ok::<_, SqlError>(children)
        })()
        .map_err(IndexReadError::Connectivity)?;
        if children.is_empty() {
            return Err(IndexInconsistency::BundleAbsent(opid).into());
        }
        Confined::try_from(children)
            .map_err(|e| IndexReadError::Connectivity(SqlError(e.to_string())))
    }

    fn bundle_info(
        &self,
        bundle_id: BundleId,
    ) -> Result<(BTreeSet<Txid>, ContractId), IndexReadError<Self::Error>> {
        let (key, has_witness, contract_blob) = (|| {
            let key = enc(&bundle_id)?;
            let db = lock(&self.db)?;
            let has_witness =
                db.exists("SELECT 1 FROM bundle_witness WHERE bundle_id = ?1", &key)?;
            let contract_blob =
                db.blob("SELECT contract_id FROM bundle_contract WHERE bundle_id = ?1", &key)?;
            Ok::<_, SqlError>((key, has_witness, contract_blob))
        })()
        .map_err(IndexReadError::Connectivity)?;
        if !has_witness {
            return Err(IndexInconsistency::BundleWitnessUnknown(bundle_id).into());
        }
        let contract_id =
            contract_blob.ok_or(IndexInconsistency::BundleContractUnknown(bundle_id))?;
        let contract_id = dec::<ContractId>(&contract_id).map_err(IndexReadError::Connectivity)?;
        let cursor = SqlKeyCursor::new(
            self.db.clone(),
            format!(
                "SELECT witness_id, witness_id FROM bundle_witness WHERE bundle_id = ?2 AND \
                 witness_id > ?1 ORDER BY witness_id LIMIT {BATCH_SIZE}"
            ),
            vec![Value::Blob(key)],
            map_decode::<Txid>,
        );
        // Eagerly collect so decode errors surface instead of being dropped.
        let witnesses = cursor
            .collect::<Result<BTreeSet<Txid>, _>>()
            .map_err(IndexReadError::Connectivity)?;
        Ok((witnesses, contract_id))
    }
}

impl IndexWriteProvider for SqlIndex {
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

    fn register_contract(&mut self, contract_id: ContractId) -> Result<bool, Self::Error> {
        let n = lock(&self.db)?.conn.execute(
            "INSERT OR IGNORE INTO registered_contract (contract_id) VALUES (?1)",
            (enc(&contract_id)?,),
        )?;
        Ok(n > 0)
    }

    fn register_bundle(
        &mut self,
        bundle_id: BundleId,
        witness_id: Txid,
        contract_id: ContractId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        let (key, existing) = (|| {
            let key = enc(&bundle_id)?;
            let existing = lock(&self.db)?
                .blob("SELECT contract_id FROM bundle_contract WHERE bundle_id = ?1", &key)?
                .map(|blob| dec::<ContractId>(&blob))
                .transpose()?;
            Ok::<_, SqlError>((key, existing))
        })()
        .map_err(IndexWriteError::Connectivity)?;
        if let Some(present) = existing.filter(|alt| *alt != contract_id) {
            return Err(IndexInconsistency::DistinctBundleContract {
                bundle_id,
                present,
                expected: contract_id,
            }
            .into());
        }
        (|| {
            let db = lock(&self.db)?;
            db.conn.execute(
                "INSERT OR IGNORE INTO bundle_witness (bundle_id, witness_id) VALUES (?1, ?2)",
                (&key, enc(&witness_id)?),
            )?;
            db.conn.execute(
                "INSERT OR REPLACE INTO bundle_contract (bundle_id, contract_id) VALUES (?1, ?2)",
                (&key, enc(&contract_id)?),
            )?;
            Ok::<_, SqlError>(())
        })()
        .map_err(IndexWriteError::Connectivity)?;
        Ok(existing.is_none())
    }

    fn register_operation(
        &mut self,
        opid: OpId,
        bundle_id: BundleId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        let (key, existing) = (|| {
            let key = enc(&opid)?;
            let existing = lock(&self.db)?
                .blob("SELECT bundle_id FROM op_bundle WHERE op_id = ?1", &key)?
                .map(|blob| dec::<BundleId>(&blob))
                .transpose()?;
            Ok::<_, SqlError>((key, existing))
        })()
        .map_err(IndexWriteError::Connectivity)?;
        if let Some(present) = existing.filter(|alt| *alt != bundle_id) {
            return Err(IndexInconsistency::DistinctBundleOp {
                opid,
                present,
                expected: bundle_id,
            }
            .into());
        }
        if existing.is_some() {
            return Ok(false);
        }
        (|| {
            lock(&self.db)?.conn.execute(
                "INSERT OR IGNORE INTO op_bundle (op_id, bundle_id) VALUES (?1, ?2)",
                (key, enc(&bundle_id)?),
            )?;
            Ok::<_, SqlError>(())
        })()
        .map_err(IndexWriteError::Connectivity)?;
        Ok(true)
    }

    fn register_spending(
        &mut self,
        opid: OpId,
        bundle_id: BundleId,
    ) -> Result<bool, IndexWriteError<Self::Error>> {
        (|| {
            let key = enc(&opid)?;
            let db = lock(&self.db)?;
            let present = db.exists("SELECT 1 FROM op_bundle_child WHERE op_id = ?1", &key)?;
            db.conn.execute(
                "INSERT OR IGNORE INTO op_bundle_child (op_id, bundle_id) VALUES (?1, ?2)",
                (key, enc(&bundle_id)?),
            )?;
            Ok(present)
        })()
        .map_err(IndexWriteError::Connectivity)
    }

    fn index_genesis_assignments<State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        vec: &[Assign<State, GenesisSeal>],
        opid: OpId,
        type_id: AssignmentType,
    ) -> Result<(), IndexWriteError<Self::Error>> {
        if !self
            .contract_registered(contract_id)
            .map_err(IndexWriteError::Connectivity)?
        {
            return Err(IndexInconsistency::ContractAbsent(contract_id).into());
        }
        (|| {
            let cid = enc(&contract_id)?;
            let db = lock(&self.db)?;
            for (no, assign) in vec.iter().enumerate() {
                let opout = enc(&Opout::new(opid, type_id, no as u16))?;
                match assign.seal {
                    BuilderSeal::Revealed(seal) => {
                        let outpoint = seal
                            .to_output_seal()
                            .expect("genesis seals always have outpoint")
                            .to_outpoint();
                        db.conn.execute(
                            "INSERT OR IGNORE INTO outpoint_opout (contract_id, txid, vout, \
                             opout) VALUES (?1, ?2, ?3, ?4)",
                            (&cid, enc(&outpoint.txid)?, i64::from(outpoint.vout), opout),
                        )?;
                    }
                    BuilderSeal::Concealed(seal) => {
                        db.conn.execute(
                            "INSERT OR IGNORE INTO terminal (secret_seal, opout) VALUES (?1, ?2)",
                            (enc(&seal)?, opout),
                        )?;
                    }
                }
            }
            Ok(())
        })()
        .map_err(IndexWriteError::Connectivity)
    }

    fn index_transition_assignments<State: ExposedState>(
        &mut self,
        contract_id: ContractId,
        vec: &[Assign<State, GraphSeal>],
        opid: OpId,
        type_id: AssignmentType,
        witness_id: Txid,
    ) -> Result<(), IndexWriteError<Self::Error>> {
        if !self
            .contract_registered(contract_id)
            .map_err(IndexWriteError::Connectivity)?
        {
            return Err(IndexInconsistency::ContractAbsent(contract_id).into());
        }
        (|| {
            let cid = enc(&contract_id)?;
            let db = lock(&self.db)?;
            for (no, assign) in vec.iter().enumerate() {
                let opout = enc(&Opout::new(opid, type_id, no as u16))?;
                match assign.seal {
                    BuilderSeal::Revealed(seal) => {
                        // Same-tx seals get the witness txid substituted
                        let outpoint = seal.to_output_seal_or_default(witness_id).to_outpoint();
                        db.conn.execute(
                            "INSERT OR IGNORE INTO outpoint_opout (contract_id, txid, vout, \
                             opout) VALUES (?1, ?2, ?3, ?4)",
                            (&cid, enc(&outpoint.txid)?, i64::from(outpoint.vout), opout),
                        )?;
                    }
                    BuilderSeal::Concealed(seal) => {
                        db.conn.execute(
                            "INSERT OR IGNORE INTO terminal (secret_seal, opout) VALUES (?1, ?2)",
                            (enc(&seal)?, opout),
                        )?;
                    }
                }
            }
            Ok(())
        })()
        .map_err(IndexWriteError::Connectivity)
    }
}
