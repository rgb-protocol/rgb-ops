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

use invoice::{Allocation, Amount};
pub use rgb::stl::{
    aluvm_stl, bp_core_stl, commit_verify_stl, rgb_commit_stl, rgb_logic_stl, LIB_ID_RGB_COMMIT,
    LIB_ID_RGB_LOGIC,
};
use rgb::validation::TypeLibs;
use rgb::Schema;
pub use strict_types::stl::bitcoin_stl;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typesys::SystemBuilder;
use strict_types::{LibBuilder, SemId, SymbolicSys, TypeLib, TypeSystem};

use super::{
    AssetSpec, AttachmentType, BurnMeta, ContractSpec, ContractTerms, EmbeddedMedia, Error,
    IssueMeta, MediaType, RejectListUrl, TokenData, LIB_NAME_RGB_CONTRACT,
};
use crate::containers::{Contract, Transfer};
use crate::stl::ProofOfReserves;
use crate::LIB_NAME_RGB_OPS;

/// Strict types id for the library providing standard data types which may be
/// used in RGB smart contracts.
pub const LIB_ID_RGB_CONTRACT: &str =
    "stl:BVTW_R~C-ynXP70a-OlhwXa8-SbXktmr-u912vW1-ztIyxhk#mayor-ballet-flood";

/// Strict types id for the library representing of RGB Ops data types.
pub const LIB_ID_RGB_OPS: &str =
    "stl:iXN1dKpE-Mrub8G4-TnKVA87-mi1~L1j-KknQv8G-HVIPvis#story-october-cloud";

/// Generates strict type library representation of RGB Ops data types.
pub fn rgb_ops_stl() -> TypeLib {
    // TODO: wait for fix in strict_types to use LibBuilder::with
    #[allow(deprecated)]
    LibBuilder::new(libname!(LIB_NAME_RGB_OPS), [
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bitcoin_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency(),
        rgb_commit_stl().to_dependency(),
        rgb_logic_stl().to_dependency(),
    ])
    .transpile::<Contract>()
    .transpile::<Transfer>()
    .compile()
    .unwrap()
}

/// Generates strict type library providing standard data types which may be
/// used in RGB smart contracts.
pub fn rgb_contract_stl() -> TypeLib {
    LibBuilder::with(libname!(LIB_NAME_RGB_CONTRACT), [
        std_stl().to_dependency_types(),
        bitcoin_stl().to_dependency_types(),
    ])
    .transpile::<Allocation>()
    .transpile::<Amount>()
    .transpile::<AssetSpec>()
    .transpile::<AttachmentType>()
    .transpile::<BurnMeta>()
    .transpile::<ContractSpec>()
    .transpile::<ContractTerms>()
    .transpile::<EmbeddedMedia>()
    .transpile::<IssueMeta>()
    .transpile::<MediaType>()
    .transpile::<ProofOfReserves>()
    .transpile::<RejectListUrl>()
    .transpile::<TokenData>()
    .compile()
    .unwrap()
}

#[derive(Debug)]
pub struct StandardTypes {
    sys: SymbolicSys,
    libs: TypeLibs,
}

impl StandardTypes {
    pub fn with(lib: TypeLib) -> Self {
        Self::try_with([std_stl(), bitcoin_stl(), rgb_contract_stl(), lib])
            .expect("error in standard RGBContract type system")
    }

    #[allow(clippy::result_large_err)]
    fn try_with(libs: impl IntoIterator<Item = TypeLib>) -> Result<Self, Error> {
        let libs = libs.into_iter().collect::<Vec<_>>();
        let mut builder = SystemBuilder::new();
        for lib in libs.iter() {
            builder = builder.import(lib.clone())?;
        }
        let sys = builder.finalize()?;
        let libs = TypeLibs::from_iter_checked(libs.into_iter().map(|lib| (lib.id(), lib)));
        Ok(Self { sys, libs })
    }

    /// The type libraries this system was built from.
    ///
    /// This is what a schema definition ships: a recipient rebuilds the type
    /// system from them, deriving every semantic id itself instead of trusting
    /// the ones it was handed.
    pub fn libs(&self) -> TypeLibs { self.libs.clone() }

    pub fn type_system(&self, schema: Schema) -> TypeSystem {
        self.sys.as_types().extract(schema.types()).unwrap()
    }

    pub fn get(&self, name: &'static str) -> SemId {
        *self.sys.resolve(name).unwrap_or_else(|| {
            panic!("type '{name}' is absent in standard RGBContract type library")
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn contract_lib_id() {
        let lib = rgb_contract_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_CONTRACT);
    }

    #[test]
    fn std_lib_id() {
        let lib = rgb_ops_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_OPS);
    }

    #[test]
    fn rgb_contract_id_standard_types() {
        use amplify::hex::FromHex;
        use rgb::stl::rgb_contract_id_stl;

        let standard_types = StandardTypes::with(rgb_contract_id_stl());
        let exp_sem_id = "9f082c493ac802a2bac5dddc0b227c20af94d468c448cf1a5a21e0bdc2f53a32";
        assert_eq!(
            standard_types.get("RGBCommit.ContractId"),
            SemId::from_hex(exp_sem_id).unwrap()
        );
    }
}
