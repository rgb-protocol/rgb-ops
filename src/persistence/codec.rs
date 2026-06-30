// RGB ops library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 RGB-Tools developers
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

//! Strict-encoding helpers shared across the persistence layer (`Stock`, its
//! readers and the SQLite backend) for the strict-encoded blobs and keys
//! exchanged with an [`RgbStore`](super::RgbStore).
//!
//! [`encode`]/[`decode`] are the canonical fallible primitives; [`enc`] (panics)
//! and [`dec_opt`] (lenient) are thin convenience wrappers, and the SQLite
//! backend wraps the same primitives into its own error type.

use std::io::{self, BufRead};

use amplify::confinement::U32 as U32MAX;
use strict_encoding::{DeserializeError, StrictDecode, StrictEncode, StrictReader, StrictWriter};

/// Strict-encodes a value into an in-memory blob; fails only on a genuine
/// serialization error.
pub fn encode<T: StrictEncode>(val: &T) -> io::Result<Vec<u8>> {
    let writer = val.strict_encode(StrictWriter::in_memory::<U32MAX>())?;
    Ok(writer.unbox().unconfine())
}

/// Strict-decodes a blob, requiring it to be consumed in full.
pub fn decode<T: StrictDecode>(blob: &[u8]) -> Result<T, DeserializeError> {
    let mut reader = StrictReader::in_memory::<U32MAX>(blob);
    let val = T::strict_decode(&mut reader)?;
    let mut cursor = reader.into_cursor();
    if !cursor.fill_buf()?.is_empty() {
        return Err(DeserializeError::DataNotEntirelyConsumed);
    }
    Ok(val)
}

/// Strict-encodes a value; panics on the impossible in-memory failure.
pub(crate) fn enc<T: StrictEncode>(val: &T) -> Vec<u8> {
    encode(val).expect("in-memory strict encoding cannot fail")
}

/// Lenient decode: `None` on any decoding failure or trailing bytes.
pub(crate) fn dec_opt<T: StrictDecode>(blob: &[u8]) -> Option<T> { decode(blob).ok() }
