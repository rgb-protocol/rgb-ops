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

use std::{iter, slice};

use amplify::confinement::{NonEmptyVec, U16};
use rgb::GraphSeal;
use strict_encoding::DefaultBasedStrictDumb;

use crate::containers::BuilderSeal;
use crate::LIB_NAME_RGB_OPS;

/// Version of the [`Consignment`](crate::containers::Consignment) container.
///
/// Single-valued on purpose: a consignment is V1 by construction, so the
/// version is carried by the type rather than by data. The leading version
/// byte still appears on the wire (the strict codec encodes the discriminant),
/// and decoding a byte other than `1` fails through `try_from_u8`, which is
/// what rejects legacy V0 streams. Those are read with
/// [`ConsignmentV0`](crate::containers::legacy::ConsignmentV0) instead.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[non_exhaustive]
#[repr(u8)]
pub enum ConsignmentVer {
    #[default]
    #[display("v1", alt = "1")]
    V1 = 1,
}

impl DefaultBasedStrictDumb for ConsignmentVer {}

/// Non-empty list of history terminal seals.
///
/// Each seal is a [`BuilderSeal`]: either concealed (only the secret hash is
/// known, for blinded transfers) or revealed (the full graph seal is known,
/// for witness-vout transfers).
#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS, dumb = Self(NonEmptyVec::with(BuilderSeal::strict_dumb())))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TerminalSeals(
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    NonEmptyVec<BuilderSeal<GraphSeal>, U16>,
);

impl<'a> IntoIterator for &'a TerminalSeals {
    type Item = BuilderSeal<GraphSeal>;
    type IntoIter = iter::Copied<slice::Iter<'a, BuilderSeal<GraphSeal>>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter().copied() }
}
