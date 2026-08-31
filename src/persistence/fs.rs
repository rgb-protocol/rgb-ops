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

use std::path::PathBuf;
use std::{fs, io};

use amplify::confinement::U32 as U32MAX;
use strict_encoding::{DeserializeError, StrictDeserialize};

#[cfg(feature = "legacy")]
use crate::persistence::MemStashV0;
use crate::persistence::{MemIndex, MemState};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct FsBinStore {
    pub stash: PathBuf,
    pub state: PathBuf,
    pub index: PathBuf,
}

impl FsBinStore {
    pub fn new(path: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&path)?;

        let mut stash = path.clone();
        stash.push("stash.dat");
        let mut state = path.clone();
        state.push("state.dat");
        let mut index = path.clone();
        index.push("index.dat");

        Ok(Self {
            stash,
            state,
            index,
        })
    }

    /// Deserializes `stash.dat` using the legacy v0 stash layout.
    #[cfg(feature = "legacy")]
    pub fn load_stash_v0(&self) -> Result<MemStashV0, DeserializeError> {
        MemStashV0::strict_deserialize_from_file::<U32MAX>(&self.stash)
    }

    pub fn load_state(&self) -> Result<MemState, DeserializeError> {
        MemState::strict_deserialize_from_file::<U32MAX>(&self.state)
    }

    pub fn load_index(&self) -> Result<MemIndex, DeserializeError> {
        MemIndex::strict_deserialize_from_file::<U32MAX>(&self.index)
    }
}
