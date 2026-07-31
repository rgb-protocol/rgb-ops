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

use aluvm::library::{Lib, LibId};
use amplify::confinement::{LargeOrdMap, LargeOrdSet, SmallOrdMap, TinyOrdMap};
use rgb::bitcoin::Txid;
use rgb::{BundleId, ContractId, Genesis, GraphSeal, Schema, SchemaId, TransitionBundle};
use strict_encoding::{StrictDeserialize, StrictEncode};
use strict_types::TypeSystem;

use crate::containers::legacy::SealWitnessV0;
use crate::LIB_NAME_RGB_STORAGE;

#[derive(Getters, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
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
