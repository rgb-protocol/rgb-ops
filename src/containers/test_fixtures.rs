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

//! Shared builders and fixture writers for container tests.

#[cfg(all(feature = "fs", feature = "serde"))]
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(all(feature = "fs", feature = "serde"))]
use rgb::validation;
use strict_encoding::{StrictSerialize, TypeName};

#[cfg(all(feature = "fs", feature = "serde"))]
use crate::containers::file::FileContent;
#[cfg(feature = "fs")]
use crate::containers::Transfer;
#[cfg(all(feature = "fs", feature = "serde"))]
use crate::containers::ValidTransfer;
use crate::containers::{ConsignmentVer, Contract};

#[cfg(all(feature = "fs", feature = "serde"))]
fn asset_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("asset")
        .join(name)
}

/// The schema definition of the almost-default schema, as a stock must hold it
/// to accept the fixtures below: a v1 consignment carries only its schema id.
#[cfg(all(feature = "fs", feature = "serde", feature = "sqlite"))]
pub(crate) fn almost_default_schema_definition() -> rgb::validation::SchemaDefinition {
    rgb::validation::SchemaDefinition::new(almost_default_schema(), none!(), none!())
}

/// A schema with almost default fields.
fn almost_default_schema() -> rgb::Schema {
    rgb::Schema {
        ffv: Default::default(),
        name: TypeName::from_str("Name").unwrap(),
        meta_types: Default::default(),
        global_types: Default::default(),
        owned_types: Default::default(),
        genesis: Default::default(),
        transitions: Default::default(),
        default_assignment: Default::default(),
    }
}

/// A genesis with almost default fields, referencing `schema`.
fn almost_default_genesis(schema: &rgb::Schema) -> rgb::Genesis {
    rgb::Genesis {
        ffv: Default::default(),
        schema_id: schema.schema_id(),
        timestamp: Default::default(),
        issuer: Default::default(),
        chain_net: Default::default(),
        seal_closing_strategy: Default::default(),
        metadata: Default::default(),
        globals: Default::default(),
        assignments: Default::default(),
    }
}

/// A contract with almost default fields.
pub fn almost_default_contract() -> Contract {
    Contract {
        version: ConsignmentVer::V1,
        transfer: Default::default(),
        terminals: Default::default(),
        genesis: almost_default_genesis(&almost_default_schema()),
        bundles: Default::default(),
    }
}

/// A transfer with almost default fields.
#[cfg(feature = "fs")]
pub fn almost_default_transfer() -> Transfer {
    Transfer {
        version: ConsignmentVer::V1,
        transfer: true,
        terminals: Default::default(),
        genesis: almost_default_genesis(&almost_default_schema()),
        bundles: Default::default(),
    }
}

/// Writes the `asset/*.default` fixtures from the builders above.
#[cfg(all(feature = "fs", feature = "serde"))]
fn write_default_fixtures() {
    almost_default_contract()
        .save_file(asset_path("contract.default"))
        .unwrap();
    almost_default_contract()
        .save_armored(asset_path("armored_contract.default"))
        .unwrap();
    almost_default_transfer()
        .save_file(asset_path("transfer.default"))
        .unwrap();
    almost_default_transfer()
        .save_armored(asset_path("armored_transfer.default"))
        .unwrap();
    ValidTransfer::from_parts(almost_default_transfer(), validation::Status::default())
        .save_file(asset_path("valid_transfer.default"))
        .unwrap();
}

/// Writes golden V1 fixtures to `asset/` from the default contract builder.
///
/// Usually invoked via `regenerate_fixtures`, which also refreshes the default
/// fixtures. Use this standalone when only v1 goldens need updating:
///
/// ```text
/// cargo test -p rgb-ops generate_v1_golden -- --ignored --nocapture
/// ```
#[test]
#[ignore = "run once to generate golden fixtures, then commit the asset/ files"]
fn generate_v1_golden() {
    let dir = env!("CARGO_MANIFEST_DIR");

    let contract = almost_default_contract();

    let bytes = contract.to_strict_serialized::<{ usize::MAX }>().unwrap();
    let commit_id = contract.consignment_id().to_string();

    std::fs::write(format!("{dir}/asset/contract_golden.bin"), bytes.as_slice())
        .expect("failed to write contract_golden.bin");
    std::fs::write(format!("{dir}/asset/contract_golden_id.txt"), &commit_id)
        .expect("failed to write contract_golden_id.txt");

    println!("wrote {} bytes, commit_id = {commit_id}", bytes.len());
}

/// Regenerates the `asset/*.default` fixtures and v1 golden files from the
/// builders above, then commit the changed files. Run this after changing a
/// builder:
///
/// ```text
/// cargo test -p rgb-ops regenerate_fixtures --features fs,serde -- --ignored
/// ```
///
/// To refresh only v1 goldens (e.g. after serialization changes), run
/// `generate_v1_golden` instead.
#[cfg(all(feature = "fs", feature = "serde"))]
#[test]
#[ignore = "run once to regenerate the asset/*.default fixtures, then commit"]
fn regenerate_fixtures() {
    write_default_fixtures();
    generate_v1_golden();
}
