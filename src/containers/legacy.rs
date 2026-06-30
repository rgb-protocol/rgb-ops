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

//! Legacy (V0) container formats.
//!
//! Duplicates the code of the V0 consignment, as it was before the V1 upgrade,
//! so that old consignment files keep decoding byte-for-byte. The only
//! supported operation besides reading/writing is the conversion to V1 via
//! [`ConsignmentV0::into_v1`]; V0 consignments cannot be validated directly.

use std::cmp::Ordering;
use std::collections::{btree_set, BTreeSet};
use std::iter;

use aluvm::library::Lib;
use amplify::confinement::{Confined, LargeVec, NonEmptyOrdSet, NonEmptyVec, SmallOrdMap, U16};
use rgb::bitcoin::Transaction as Tx;
use rgb::commit_verify::mpc;
use rgb::dbc::Anchor;
use rgb::validation::{
    DbcProof, ResolveWitness, WitnessResolverError, WitnessStatus, CONSIGNMENT_MAX_LIBS,
};
use rgb::{BundleId, ContractId, Genesis, Operation, Schema, SchemaId, TransitionBundle, Txid};
use strict_encoding::{DefaultBasedStrictDumb, StrictDeserialize, StrictDumb, StrictSerialize};
use strict_types::TypeSystem;

use crate::containers::{
    BuilderSeal, Consignment, ConsignmentVer, SealWitness, TerminalSeals, WitnessBundle,
};
use crate::{SecretSeal, LIB_NAME_RGB_OPS};

pub type TransferV0 = ConsignmentV0<true>;
pub type ContractV0 = ConsignmentV0<false>;

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS, tags = custom, dumb = Self::Tx(strict_dumb!()))]
pub enum PubWitness {
    #[strict_type(tag = 0x00)]
    Txid(Txid),
    #[strict_type(tag = 0x01)]
    Tx(Tx),
}

impl PartialEq for PubWitness {
    fn eq(&self, other: &Self) -> bool { self.txid() == other.txid() }
}

impl Ord for PubWitness {
    fn cmp(&self, other: &Self) -> Ordering { self.txid().cmp(&other.txid()) }
}

impl PartialOrd for PubWitness {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl PubWitness {
    pub fn txid(&self) -> Txid {
        match self {
            PubWitness::Txid(txid) => *txid,
            PubWitness::Tx(tx) => tx.compute_txid(),
        }
    }

    pub fn into_v1(self, resolver: Option<&dyn ResolveWitness>) -> Result<Tx, IntoV1Error> {
        match self {
            PubWitness::Txid(txid) => {
                let Some(r) = resolver else {
                    return Err(IntoV1Error::NoResolver(txid));
                };
                match r.resolve_witness(txid)? {
                    WitnessStatus::Resolved(tx, _) => Ok(tx),
                    WitnessStatus::Unresolved => Err(IntoV1Error::Unresolved(txid)),
                }
            }
            PubWitness::Tx(tx) => Ok(tx),
        }
    }
}

/// V0 seal witness: like [`crate::containers::SealWitness`], but with a
/// possibly unresolved [`PubWitness`] and no SPV proof.
///
/// Only used to read a legacy stash (see
/// [`crate::persistence::MemStashV0`]); converting it to V1 requires the full
/// transaction, so it goes through [`SealWitnessV0::into_v1`].
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
pub struct SealWitnessV0 {
    pub public: PubWitness,
    pub merkle_block: mpc::MerkleBlock,
    pub dbc_proof: DbcProof,
}

impl SealWitnessV0 {
    /// Converts into a V1 [`SealWitness`], resolving the witness transaction
    /// through `resolver` when this V0 witness only holds a txid.
    pub fn into_v1(
        self,
        resolver: Option<&dyn ResolveWitness>,
    ) -> Result<SealWitness, IntoV1Error> {
        Ok(SealWitness {
            tx: self.public.into_v1(resolver)?,
            mpc_merkle_block: self.merkle_block,
            dbc_proof: self.dbc_proof,
            spv_proof: None,
        })
    }
}

/// Version of the legacy [`ConsignmentV0`] container.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS, tags = repr, into_u8, try_from_u8)]
#[non_exhaustive]
#[repr(u8)]
pub enum ContainerVerV0 {
    #[default]
    #[display("v0", alt = "0")]
    V0 = 0,
}

impl DefaultBasedStrictDumb for ContainerVerV0 {}

/// Non-empty set of secret seals: the V0 terminal seal format (V0 terminals
/// are always concealed).
#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS, dumb = Self(NonEmptyOrdSet::with(SecretSeal::strict_dumb())))]
pub struct SecretSeals(NonEmptyOrdSet<SecretSeal, U16>);

impl<'a> IntoIterator for &'a SecretSeals {
    type Item = SecretSeal;
    type IntoIter = iter::Copied<btree_set::Iter<'a, SecretSeal>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter().copied() }
}

/// V0 witness bundle: like [`WitnessBundle`], but without the SPV proof.
#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
pub struct WitnessBundleV0 {
    pub pub_witness: PubWitness,
    pub anchor: Anchor<DbcProof>,
    pub bundle: TransitionBundle,
}

impl PartialEq for WitnessBundleV0 {
    fn eq(&self, other: &Self) -> bool { self.pub_witness == other.pub_witness }
}

impl Ord for WitnessBundleV0 {
    fn cmp(&self, other: &Self) -> Ordering { self.pub_witness.cmp(&other.pub_witness) }
}

impl PartialOrd for WitnessBundleV0 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

/// Error converting a [`ConsignmentV0`] into a V1 [`Consignment`].
#[derive(Debug, Display, Error, From)]
pub enum IntoV1Error {
    #[display("no resolver provided for bare Txid {0}")]
    NoResolver(Txid),
    #[display("witness {0} could not be resolved")]
    Unresolved(Txid),
    #[display(inner)]
    #[from]
    Resolver(WitnessResolverError),
}

/// Legacy V0 consignment.
///
/// Preserves the original V0 wire format: concealed-only terminals, bundles
/// with the [`PubWitness`] enum and no SPV proof, and an embedded type system.
///
/// V0 consignments cannot be validated; convert them to V1 with
/// [`Self::into_v1`] and validate the resulting [`Consignment`].
#[derive(Clone, Debug, PartialEq)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
pub struct ConsignmentV0<const TRANSFER: bool> {
    /// Version.
    pub version: ContainerVerV0,

    /// Specifies whether the consignment contains information about state
    /// transfer (true), or it is just a consignment with an information about a
    /// contract.
    pub transfer: bool,

    /// Set of secret seals which are history terminals.
    pub terminals: SmallOrdMap<BundleId, SecretSeals>,

    /// Genesis data.
    pub genesis: Genesis,

    /// All bundled state transitions contained in the consignment, together
    /// with their witness data.
    pub bundles: LargeVec<WitnessBundleV0>,

    /// Schema (plus root schema, if any) under which contract is issued.
    pub schema: Schema,

    /// Type system covering all types used in schema.
    pub types: TypeSystem,

    /// Collection of scripts used across consignment.
    pub scripts: Confined<BTreeSet<Lib>, 0, CONSIGNMENT_MAX_LIBS>,
}

impl<const TRANSFER: bool> StrictSerialize for ConsignmentV0<TRANSFER> {}
impl<const TRANSFER: bool> StrictDeserialize for ConsignmentV0<TRANSFER> {}

impl<const TRANSFER: bool> ConsignmentV0<TRANSFER> {
    #[inline]
    pub fn contract_id(&self) -> ContractId { self.genesis.contract_id() }

    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.schema.schema_id() }

    /// Converts this legacy V0 consignment into a V1 [`Consignment`].
    ///
    /// V1 consignments always carry the full witness transactions, so bundles
    /// referencing a bare [`PubWitness::Txid`] need `resolver` to retrieve the
    /// transaction; the embedded schema, type system and scripts are dropped
    /// (V1 distributes all three out-of-band via schema definitions) and the concealed
    /// terminals are mapped to V1 terminal seals.
    pub fn into_v1(
        self,
        resolver: Option<&dyn ResolveWitness>,
    ) -> Result<Consignment<TRANSFER>, IntoV1Error> {
        let mut bundles = Vec::with_capacity(self.bundles.len());
        for bundle in self.bundles {
            bundles.push(WitnessBundle {
                tx: bundle.pub_witness.into_v1(resolver)?,
                spv_proof: None,
                anchor: bundle.anchor,
                bundle: bundle.bundle,
            });
        }

        let terminals = SmallOrdMap::from_iter_checked(self.terminals.into_iter().map(
            |(bundle_id, secrets)| {
                let seals =
                    NonEmptyVec::from_iter_checked(secrets.into_iter().map(BuilderSeal::Concealed));
                (bundle_id, TerminalSeals::from(seals))
            },
        ));

        Ok(Consignment {
            version: ConsignmentVer::V1,
            transfer: self.transfer,
            terminals,
            genesis: self.genesis,
            bundles: LargeVec::from_iter_checked(bundles),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn v0_strict_encode_round_trip() {
        let v0 = ConsignmentV0::<false>::strict_dumb();
        let bytes = v0.to_strict_serialized::<{ usize::MAX }>().unwrap();
        assert_eq!(bytes[0], 0, "V0 encoding must start with the V0 version byte");
        let decoded =
            ConsignmentV0::<false>::from_strict_serialized::<{ usize::MAX }>(bytes).unwrap();
        assert_eq!(decoded, v0, "V0 strict encode round trip fails");
    }

    /// Reads a genuine pre-V1 consignment, produced by this code base before
    /// the V1 upgrade, so it exercises the parts of the V0 wire that actually
    /// differ from V1: concealed-only terminals, [`WitnessBundleV0`] (no SPV
    /// proof, [`PubWitness`] witnesses) and an embedded type system.
    #[test]
    fn historical_v0_file_round_trip() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/asset/historical_transfer_v0.rgb");
        let bytes = std::fs::read(path).expect("missing historical V0 fixture");
        assert_eq!(bytes[0], 0, "fixture must be a V0 consignment");

        let transfer =
            TransferV0::strict_deserialize_from_file::<{ usize::MAX }>(path).expect("V0 decode");
        assert!(!transfer.bundles.is_empty(), "fixture must carry bundles");
        assert!(!transfer.terminals.is_empty(), "fixture must carry terminals");
        assert!(!transfer.types.is_empty(), "fixture must carry an embedded type system");

        let reencoded = transfer
            .to_strict_serialized::<{ usize::MAX }>()
            .unwrap()
            .release();
        assert_eq!(reencoded, bytes, "V0 re-encoding must be byte-identical");
    }

    /// The historical V0 file converts to V1 without a resolver, since its
    /// bundles carry full witness transactions.
    #[test]
    fn historical_v0_into_v1() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/asset/historical_transfer_v0.rgb");
        let v0 = TransferV0::strict_deserialize_from_file::<{ usize::MAX }>(path).unwrap();
        let bundles = v0.bundles.len();
        let terminals = v0.terminals.len();

        let v1 = v0.into_v1(None).expect("conversion to V1");
        assert_eq!(v1.bundles.len(), bundles);
        assert_eq!(v1.terminals.len(), terminals);
        // every V0 terminal seal is concealed, and stays so in V1
        assert!(v1
            .terminals
            .values()
            .flat_map(|seals| seals.into_iter())
            .all(|seal| matches!(seal, BuilderSeal::Concealed(_))));
    }

    #[test]
    fn v0_into_v1() {
        let contract_v0 = ContractV0::strict_dumb();
        let genesis = contract_v0.genesis.clone();
        // no bundles with bare txids, so no resolver is needed
        let contract = contract_v0.into_v1(None).unwrap();
        assert_eq!(contract.version, ConsignmentVer::V1);
        assert_eq!(contract.genesis, genesis);
    }
}
