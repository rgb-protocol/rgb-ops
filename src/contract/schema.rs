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

use crate::contract::{ContractData, ContractStateRead};
use crate::validation::{SchemaDefinition, SchemaRules, Scripts, TypeLibs};
use crate::Schema;

/// The instances implementing this trait are used as wrappers around [`ContractData`] object,
/// allowing a simple API matching the schema requirements.
pub trait SchemaWrapper<S: ContractStateRead> {
    fn with(data: ContractData<S>) -> Self;
}

pub trait IssuerWrapper {
    type Wrapper<S: ContractStateRead>: SchemaWrapper<S>;

    fn schema() -> Schema;
    /// The strict type libraries the schema's semantic ids are defined in.
    ///
    /// The type system is derived from these, never shipped directly: that is
    /// what lets a recipient authenticate the type definitions against the
    /// semantic ids the schema commits to.
    fn libs() -> TypeLibs;
    fn scripts() -> Scripts;

    /// The [`SchemaDefinition`] of this schema: the serializable form, carrying
    /// the type libraries rather than the type system built from them.
    fn schema_definition() -> SchemaDefinition {
        SchemaDefinition::new(Self::schema(), Self::libs(), Self::scripts())
    }

    /// The verified [`SchemaRules`] of this schema.
    ///
    /// # Panics
    ///
    /// If the schema, its type libraries and its scripts are inconsistent,
    /// which for a built-in schema is a bug.
    fn schema_rules() -> SchemaRules {
        Self::schema_definition()
            .verify()
            .expect("inconsistent built-in schema definition")
    }
}
