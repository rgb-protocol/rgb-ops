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

//! Frozen layouts and loaders for the pre-SQLite persistence backend.
//!
//! The legacy in-memory backend persisted three strict-encoded files:
//! `stash.dat`, `state.dat` and `index.dat`. This module keeps their v0
//! deserialization types and a read-only directory accessor so a caller can
//! migrate them into a new [`RgbStore`](super::RgbStore) backend. The format
//! is never written again.

use std::path::PathBuf;

use aluvm::library::{Lib, LibId};
use amplify::confinement::{
    LargeOrdMap, LargeOrdSet, MediumOrdSet, SmallOrdMap, SmallOrdSet, TinyOrdMap, U32 as U32MAX,
};
use rgb::bitcoin::Txid;
use rgb::vm::WitnessOrd;
use rgb::{
    BundleId, ContractId, Genesis, GraphSeal, OpId, Opout, OutputSeal, Schema, SchemaId,
    SecretSeal, TransitionBundle,
};
use strict_encoding::{DefaultBasedStrictDumb, DeserializeError, StrictDeserialize};
use strict_types::TypeSystem;

use crate::containers::legacy::SealWitnessV0;
use crate::contract::UnfilteredContractState;
use crate::LIB_NAME_RGB_STORAGE;

#[derive(Getters, Debug)]
#[derive(StrictType, StrictDumb, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemStashV0 {
    schemata: TinyOrdMap<SchemaId, Schema>,
    geneses: SmallOrdMap<ContractId, Genesis>,
    bundles: LargeOrdMap<BundleId, TransitionBundle>,
    witnesses: LargeOrdMap<Txid, SealWitnessV0>,
    secret_seals: LargeOrdSet<GraphSeal>,
    type_system: TypeSystem,
    libs: SmallOrdMap<LibId, Lib>,
}

impl StrictDeserialize for MemStashV0 {}

impl MemStashV0 {
    pub fn in_memory() -> Self {
        Self {
            schemata: empty!(),
            geneses: empty!(),
            bundles: empty!(),
            witnesses: empty!(),
            secret_seals: empty!(),
            type_system: none!(),
            libs: empty!(),
        }
    }
}

#[derive(Getters, Debug)]
#[derive(StrictType, StrictDumb, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemStateV0 {
    witnesses: LargeOrdMap<Txid, WitnessOrd>,
    invalid_ops: LargeOrdSet<OpId>,
    contracts: SmallOrdMap<ContractId, UnfilteredContractState>,
}

impl StrictDeserialize for MemStateV0 {}

impl MemStateV0 {
    pub fn in_memory() -> Self {
        Self {
            witnesses: empty!(),
            invalid_ops: empty!(),
            contracts: empty!(),
        }
    }
}

#[derive(Getters, Clone, Debug, Default)]
#[derive(StrictType, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE)]
pub struct ContractIndex {
    public_opouts: LargeOrdSet<Opout>,
    outpoint_opouts: LargeOrdMap<OutputSeal, MediumOrdSet<Opout>>,
}

impl DefaultBasedStrictDumb for ContractIndex {}

#[derive(Getters, Debug)]
#[derive(StrictType, StrictDumb, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_STORAGE, dumb = Self::in_memory())]
pub struct MemIndexV0 {
    op_bundle_children_index: LargeOrdMap<OpId, SmallOrdSet<BundleId>>,
    op_bundle_index: LargeOrdMap<OpId, BundleId>,
    bundle_contract_index: LargeOrdMap<BundleId, ContractId>,
    bundle_witness_index: LargeOrdMap<BundleId, LargeOrdSet<Txid>>,
    contract_index: SmallOrdMap<ContractId, ContractIndex>,
    /// V0 name for what is now the secret-seal->opout index: kept as v0 wrote
    /// it, since this type mirrors the frozen v0 layout.
    terminal_index: LargeOrdMap<SecretSeal, MediumOrdSet<Opout>>,
}

impl StrictDeserialize for MemIndexV0 {}

impl MemIndexV0 {
    pub fn in_memory() -> Self {
        Self {
            op_bundle_children_index: empty!(),
            op_bundle_index: empty!(),
            bundle_contract_index: empty!(),
            bundle_witness_index: empty!(),
            contract_index: empty!(),
            terminal_index: empty!(),
        }
    }
}

/// Read-only accessor over a legacy RGB store directory. Resolves the three
/// strict-encoded dump files and decodes them under their frozen v0 layouts for
/// one-shot migration into a new [`RgbStore`](super::RgbStore) backend.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct LegacyFsStore {
    pub stash: PathBuf,
    pub state: PathBuf,
    pub index: PathBuf,
}

impl LegacyFsStore {
    /// Points at the `stash.dat`, `state.dat` and `index.dat` files inside
    /// `path`. Does not touch the filesystem; the files are read on demand by
    /// the `load_*` methods.
    pub fn new(path: PathBuf) -> Self {
        let mut stash = path.clone();
        stash.push("stash.dat");
        let mut state = path.clone();
        state.push("state.dat");
        let mut index = path;
        index.push("index.dat");
        Self {
            stash,
            state,
            index,
        }
    }

    /// Deserializes `stash.dat` using the legacy v0 stash layout.
    pub fn load_stash_v0(&self) -> Result<MemStashV0, DeserializeError> {
        MemStashV0::strict_deserialize_from_file::<U32MAX>(&self.stash)
    }

    /// Deserializes `state.dat` using the legacy v0 state layout.
    pub fn load_state_v0(&self) -> Result<MemStateV0, DeserializeError> {
        MemStateV0::strict_deserialize_from_file::<U32MAX>(&self.state)
    }

    /// Deserializes `index.dat` using the legacy v0 index layout.
    pub fn load_index_v0(&self) -> Result<MemIndexV0, DeserializeError> {
        MemIndexV0::strict_deserialize_from_file::<U32MAX>(&self.index)
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;

    use flate2::read::GzDecoder;

    use super::*;

    /// Fixtures written by rgb-ops 0.11.1-rc.11 through its own `FsBinStore`,
    /// i.e. by the code that produced the files users may still have on disk.
    /// Kept gzipped, one file each, and expanded into a temp directory by
    /// [`unpack_fixtures`] so that the real [`LegacyFsStore`] path is what the
    /// test drives.
    const V0_DIR: &str = "asset/legacy_v0";
    const V0_FILES: [&str; 3] = ["stash.dat", "state.dat", "index.dat"];

    /// Expands the gzipped fixtures into a fresh temp directory and returns a
    /// store pointed at it. The directory is left behind for inspection when a
    /// test fails; it is small and lives under the system temp dir.
    fn unpack_fixtures() -> LegacyFsStore {
        let dir = std::env::temp_dir().join(format!("rgb-ops-v0-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp dir for v0 fixtures");
        for name in V0_FILES {
            let gz = fs::File::open(PathBuf::from(V0_DIR).join(format!("{name}.gz")))
                .unwrap_or_else(|e| panic!("open {name}.gz: {e}"));
            let mut raw = Vec::new();
            GzDecoder::new(gz)
                .read_to_end(&mut raw)
                .unwrap_or_else(|e| panic!("gunzip {name}: {e}"));
            fs::write(dir.join(name), raw).expect("write unpacked fixture");
        }
        LegacyFsStore::new(dir)
    }

    /// The v0 layouts still decode.
    ///
    /// This is the only guard on the shape of [`MemStashV0`], [`MemStateV0`],
    /// [`MemIndexV0`] and everything they reach - [`SealWitnessV0`],
    /// [`ContractIndex`], and `UnfilteredContractState`/`UnfilteredGlobalState`
    /// over in `contract::state`. Strict decoding is length-checked and
    /// `strict_deserialize_from_file` requires the blob to be consumed in full,
    /// so any field added to, removed from, reordered within or retyped in any
    /// of them fails this test rather than silently making old stores
    /// unreadable.
    ///
    /// The fixtures deliberately carry at least one element in most
    /// collections: an empty confined collection encodes as a bare length
    /// prefix and would pin nothing about its element type. Still empty, and so
    /// still unpinned, are `MemStashV0::libs`, `MemStateV0::invalid_ops` and
    /// `MemIndexV0::terminal_index` - all collections of simple id types.
    ///
    /// Regenerating these files means checking out 0.11.1-rc.11 and driving its
    /// `FsBinStore`; they cannot be produced from this version, which has no
    /// `StrictEncode` for the v0 types on purpose.
    #[test]
    fn v0_fixtures_still_decode() {
        let store = unpack_fixtures();

        let stash = store.load_stash_v0().expect("v0 stash must still decode");
        assert_eq!(stash.schemata().len(), 1);
        assert_eq!(stash.geneses().len(), 1);
        assert_eq!(stash.bundles().len(), 1);
        assert_eq!(stash.witnesses().len(), 1, "pins SealWitnessV0");
        assert_eq!(stash.secret_seals().len(), 1);

        let state = store.load_state_v0().expect("v0 state must still decode");
        assert_eq!(state.witnesses().len(), 1);
        assert_eq!(state.contracts().len(), 1);
        let (contract_id, contract) = state.contracts().first_key_value().unwrap();
        assert_eq!(contract.contract_id(), *contract_id);
        // one assignment of each family: pins OutputAssignment<_> for all three
        assert_eq!(contract.rights().len(), 1);
        assert_eq!(contract.fungibles().len(), 1);
        assert_eq!(contract.data().len(), 1);
        // one global entry, filed under a GlobalOut: pins UnfilteredGlobalState
        let (_, global) = contract.global().first_key_value().unwrap();
        assert_eq!(global.known().len(), 1);

        let index = store.load_index_v0().expect("v0 index must still decode");
        assert_eq!(index.op_bundle_index().len(), 1);
        assert_eq!(index.op_bundle_children_index().len(), 1);
        assert_eq!(index.bundle_contract_index().len(), 1);
        assert_eq!(index.bundle_witness_index().len(), 1);
        assert_eq!(index.contract_index().len(), 1, "pins ContractIndex");

        // the three files describe one contract, consistently
        assert_eq!(index.bundle_contract_index().values().next(), Some(contract_id));
        assert!(index.contract_index().contains_key(contract_id));

        let _ = fs::remove_dir_all(store.stash.parent().unwrap());
    }
}
