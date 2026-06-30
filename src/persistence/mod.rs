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

//! Data persistence layer for RGB contracts.
//!
//! All persistent data is exposed through a single backend-agnostic
//! [`RgbStore`] trait, driven by [`Stock`]. The data comprises:
//! 1. Consensus-critical client-side-validation data.
//! 2. Contract state, updated with each consumed consignment and fascia.
//! 3. Indexes to simplify operations.
//!
//! # Concurrency
//!
//! A [`Stock`] owns its store exclusively - the SQLite store is deliberately
//! not `Clone` - so two stocks over the same database are two connections and
//! never two owners of one transaction. A store transaction belongs to the
//! connection it was opened on, which is why sharing one is not offered.
//!
//! Readers are free to run alongside each other: [`Stock::contract_state`] and
//! the other read accessors take `&self` and hold no state, so several threads
//! may read one stock at once, while mutating it needs `&mut self` and is
//! therefore excluded for as long as any reader lives.
//!
//! Writers run **one at a time**, and that is enforced rather than assumed. A
//! unit of work takes the database's write lock upfront (`BEGIN IMMEDIATE`)
//! and makes every read it decides a write from *inside* that transaction, so
//! two writers - two stocks in this process, or two processes - are serialized
//! by SQLite instead of interleaved, and neither can commit on the strength of
//! a view the other has since invalidated. A writer which finds the lock taken
//! waits out the connection's busy timeout and is then told
//! [`Busy`](sqlite::SqliteError::Busy) rather than made to wait forever.
//!
//! What a unit of work has to wait on *outside* the database - a resolver
//! reaching an indexer over the network - is done before that transaction
//! opens, so no write lock is held across a network round-trip. Reads made out
//! there only pick what to ask about; what gets stored on the strength of the
//! answers is decided again from reads made under the lock.

mod stock;
mod error;
mod store;
mod codec;
mod reader;

#[cfg(feature = "legacy")]
mod legacy;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use aluvm::library::{Lib, LibId};
pub use codec::{decode, encode};
pub use error::{
    ComposeError, ConsignError, ContractStateError, DataError, FasciaError, Inconsistency,
    InputError as StockInputError, StockError, StockErrorAll,
};
#[cfg(feature = "legacy")]
pub use legacy::{LegacyFsStore, MemIndexV0, MemStashV0, MemStateV0};
pub use reader::ContractStateSnapshot;
pub use stock::{ConsignmentWithDag, ContractAssignments, RetrievedSpvProofs, Stock, UpdateRes};
pub use store::{
    AllocKind, AllocSeal, AllocationFilter, AllocationRow, AllocationWrite, GlobalStateRow,
    GlobalStateWrite, RgbStore, TxBegin, TxMode, Visibility,
};
