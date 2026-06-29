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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::str::FromStr;

use amplify::confinement::{LargeVec, SmallOrdMap};
use amplify::{ByteArray, Bytes32};
use armor::{ArmorHeader, AsciiArmor, StrictArmor};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use rgb::bitcoin::Transaction as Tx;
use rgb::commit_verify::{CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use rgb::validation::{
    EAnchor, ExternalAnchor, Failure, ResolveWitness, SchemaRules, ValidationConfig,
    ValidationError, Validator,
};
use rgb::vm::OrdOpRef;
use rgb::{
    impl_serde_baid64, validation, BundleId, ContractId, Genesis, GraphSeal, Operation, SchemaId,
    TransitionBundle, Txid,
};
use rgbcore::validation::ConsignmentApi;
use strict_encoding::{
    DeserializeError, SerializeError, StrictDeserialize, StrictDumb, StrictSerialize,
};

use super::{
    BuilderSeal, ConsignmentVer, TerminalSeals, WitnessBundle, ASCII_ARMOR_CONSIGNMENT_TYPE,
    ASCII_ARMOR_CONTRACT, ASCII_ARMOR_SCHEMA, ASCII_ARMOR_TERMINAL, ASCII_ARMOR_VERSION,
};
use crate::containers::anchors::SpvProof;
use crate::contract::{ContractData, FilteredContractState, UnfilteredContractState};
use crate::info::ContractInfo;
use crate::{SecretSeal, LIB_NAME_RGB_OPS};

pub type Transfer = Consignment<true>;
pub type Contract = Consignment<false>;

pub trait ConsignmentExt {
    fn contract_id(&self) -> ContractId;
    fn schema_id(&self) -> SchemaId;
    fn genesis(&self) -> &Genesis;
    fn bundled_witnesses(&self) -> impl Iterator<Item = &WitnessBundle>;
}

impl<C: ConsignmentExt> ConsignmentExt for &C {
    #[inline]
    fn contract_id(&self) -> ContractId { (*self).contract_id() }

    #[inline]
    fn schema_id(&self) -> SchemaId { (*self).schema_id() }

    #[inline]
    fn genesis(&self) -> &Genesis { (*self).genesis() }

    #[inline]
    fn bundled_witnesses(&self) -> impl Iterator<Item = &WitnessBundle> {
        (*self).bundled_witnesses()
    }
}

/// Consignment identifier.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
pub struct ConsignmentId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for ConsignmentId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for ConsignmentId {
    const TAG: &'static str = "urn:lnp-bp:rgb:consignment#2024-03-11";
}

impl DisplayBaid64 for ConsignmentId {
    const HRI: &'static str = "rgb:csg";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = true;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for ConsignmentId {}
impl FromStr for ConsignmentId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for ConsignmentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl_serde_baid64!(ConsignmentId);

impl ConsignmentId {
    pub const fn from_array(id: [u8; 32]) -> Self { Self(Bytes32::from_array(id)) }
}

pub type ValidContract = ValidConsignment<false>;
pub type ValidTransfer = ValidConsignment<true>;

#[derive(Clone, Debug, Display)]
#[display("{consignment}")]
pub struct ValidConsignment<const TRANSFER: bool> {
    /// Status of the latest validation.
    validation_status: validation::Status,
    consignment: Consignment<TRANSFER>,
}

impl<const TRANSFER: bool> ValidConsignment<TRANSFER> {
    #[cfg(any(all(feature = "fs", feature = "serde"), test))]
    pub(crate) fn from_parts(
        consignment: Consignment<TRANSFER>,
        validation_status: validation::Status,
    ) -> Self {
        Self {
            validation_status,
            consignment,
        }
    }

    pub fn validation_status(&self) -> &validation::Status { &self.validation_status }

    pub fn into_consignment(self) -> Consignment<TRANSFER> { self.consignment }

    pub fn into_validation_status(self) -> validation::Status { self.validation_status }

    pub fn into_valid_contract(self) -> ValidContract {
        ValidContract {
            // once/if we begin collecting warnings on genesis we need to change this
            validation_status: validation::Status::default(),
            consignment: self.consignment.into_contract(),
        }
    }

    pub fn split(self) -> (Consignment<TRANSFER>, validation::Status) {
        (self.consignment, self.validation_status)
    }

    /// Build the [`ContractData`] of this consignment under the given rules.
    ///
    /// The rules must be the ones the consignment was validated against;
    /// [`crate::persistence::Stock::consignment_data`] takes them from the
    /// store so that callers cannot pair a consignment with foreign rules.
    pub(crate) fn build_contract_data(
        &self,
        rules: &SchemaRules,
    ) -> ContractData<FilteredContractState> {
        let mut unfiltered =
            UnfilteredContractState::new(rules.schema(), self.consignment.contract_id());
        unfiltered.add_operation(OrdOpRef::Genesis(&self.consignment.genesis));

        let filter = if TRANSFER {
            let mut filter = HashMap::new();
            for (transition, witness_id, bundle_id) in
                self.bundles.iter().flat_map(|witness_bundle| {
                    let witness_id = witness_bundle.witness_id();
                    let bundle_id = witness_bundle.bundle.bundle_id();
                    witness_bundle
                        .bundle
                        .known_transitions
                        .iter()
                        .map(move |known_transition| {
                            (&known_transition.transition, witness_id, bundle_id)
                        })
                })
            {
                let ord = self.validation_status.tx_ord_map.get(&witness_id).unwrap();
                filter.insert(witness_id, *ord);
                unfiltered.add_operation(OrdOpRef::Transition(transition, witness_id, bundle_id));
            }
            filter
        } else {
            HashMap::new()
        };

        let state = FilteredContractState::new(filter, BTreeSet::new(), unfiltered);
        let info = ContractInfo::with(&self.consignment.genesis);
        ContractData {
            state,
            rules: rules.clone(),
            info,
        }
    }
}

impl<const TRANSFER: bool> Deref for ValidConsignment<TRANSFER> {
    type Target = Consignment<TRANSFER>;

    fn deref(&self) -> &Self::Target { &self.consignment }
}

/// Consignment represents contract-specific data, always starting with genesis,
/// which must be valid under client-side-validation rules (i.e. internally
/// consistent and properly committed into the commitment layer, like bitcoin
/// blockchain or current state of the lightning channel).
///
/// All consignments-related procedures, including validation or merging
/// consignments data into the store or schema-specific data storage, must start
/// with `endpoints` and process up to the genesis.
#[derive(Clone, Debug, PartialEq, Display)]
#[display(AsciiArmor::to_ascii_armored_string)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
// NB: only Serialize is derived, not Deserialize since it would bypass the
// structural bounds defined by the Confined trait
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Consignment<const TRANSFER: bool> {
    /// Version.
    pub version: ConsignmentVer,

    /// Specifies whether the consignment contains information about state
    /// transfer (true), or it is just a consignment with an information about a
    /// contract.
    pub transfer: bool,

    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    pub terminals: SmallOrdMap<BundleId, TerminalSeals>,

    /// Genesis data.
    pub genesis: Genesis,

    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    /// All bundled state transitions contained in the consignment, together
    /// with their witness data.
    pub bundles: LargeVec<WitnessBundle>,
}

impl<const TRANSFER: bool> StrictSerialize for Consignment<TRANSFER> {}
impl<const TRANSFER: bool> StrictDeserialize for Consignment<TRANSFER> {}

impl<const TRANSFER: bool> CommitEncode for Consignment<TRANSFER> {
    type CommitmentId = ConsignmentId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.version);
        e.commit_to_serialized(&self.transfer);

        e.commit_to_serialized(&self.contract_id());
        e.commit_to_serialized(&self.genesis.disclose_hash());

        e.commit_to_list(&LargeVec::from_iter_checked(
            self.bundles.iter().map(WitnessBundle::commit_id),
        ));
        e.commit_to_map(&self.terminals);
    }
}

impl<const TRANSFER: bool> ConsignmentExt for Consignment<TRANSFER> {
    #[inline]
    fn contract_id(&self) -> ContractId { self.genesis.contract_id() }

    #[inline]
    fn schema_id(&self) -> SchemaId { self.genesis.schema_id }

    #[inline]
    fn genesis(&self) -> &Genesis { &self.genesis }

    #[inline]
    fn bundled_witnesses(&self) -> impl Iterator<Item = &WitnessBundle> { self.bundles.iter() }
}

impl<const TRANSFER: bool> ConsignmentApi for Consignment<TRANSFER> {
    fn genesis(&self) -> &Genesis { &self.genesis }

    fn bundles_info(
        &self,
    ) -> impl Iterator<Item = (&TransitionBundle, &EAnchor, &Tx, Option<&SpvProof>)> {
        self.bundles
            .iter()
            .map(|wb| (&wb.bundle, &wb.anchor, &wb.tx, wb.spv_proof.as_ref()))
    }

    fn terminals(&self) -> BTreeMap<BundleId, BTreeSet<BuilderSeal<GraphSeal>>> {
        self.terminals
            .iter()
            .map(|(bundle_id, seals)| (*bundle_id, seals.into_iter().collect()))
            .collect()
    }
}

impl<const TRANSFER: bool> Consignment<TRANSFER> {
    #[inline]
    pub fn consignment_id(&self) -> ConsignmentId { self.commit_id() }

    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.genesis.schema_id }

    /// Reveals the terminal seals whose secret `f` can answer for.
    ///
    /// `bundle_ids` must carry the id of each bundle, aligned with
    /// [`Self::bundles`]: every caller has the ids computed already, so they
    /// are taken rather than re-hashed here.
    pub(crate) fn reveal_terminal_seals<E>(
        mut self,
        bundle_ids: impl IntoIterator<Item = BundleId>,
        f: impl Fn(SecretSeal) -> Result<Option<GraphSeal>, E>,
    ) -> Result<Self, E> {
        for (witness_bundle, bundle_id) in self.bundles.iter_mut().zip(bundle_ids) {
            let Some(terminal_seals) = self.terminals.get_mut(&bundle_id) else {
                continue;
            };
            for terminal_seal in terminal_seals.iter_mut() {
                let BuilderSeal::Concealed(secret) = *terminal_seal else {
                    // Nothing to reveal for already revealed terminals
                    continue;
                };
                if let Some(seal) = f(secret)? {
                    // Reveal the seal both inside the bundle transitions and in
                    // the terminal entry, keeping them consistent with each other
                    witness_bundle.bundle.reveal_seal(seal);
                    terminal_seal.reveal(seal);
                }
            }
        }
        Ok(self)
    }

    pub fn into_contract(self) -> Contract {
        Contract {
            version: self.version,
            transfer: false,
            genesis: self.genesis,
            terminals: none!(),
            bundles: none!(),
        }
    }

    /// Validates the consignment against caller-supplied [`SchemaRules`].
    pub fn validate(
        self,
        rules: &SchemaRules,
        resolver: &impl ResolveWitness,
        validation_config: &ValidationConfig,
    ) -> Result<ValidConsignment<TRANSFER>, ValidationError> {
        if self.transfer != TRANSFER {
            return Err(ValidationError::InvalidConsignment(Failure::Custom(s!(
                "invalid consignment type"
            ))));
        }
        if !self.transfer && (!self.bundles.is_empty() || !self.terminals.is_empty()) {
            return Err(ValidationError::InvalidConsignment(Failure::Custom(s!(
                "contract consignment must not contain bundles nor terminals"
            ))));
        }

        let status = Validator::<FilteredContractState<UnfilteredContractState>, _>::validate(
            &self,
            rules,
            &resolver,
            (rules.schema(), self.contract_id()),
            validation_config,
        )?;

        Ok(ValidConsignment {
            validation_status: status,
            consignment: self,
        })
    }

    /// Variant of [`Self::validate`] for BFA (Bridged Fungible Asset) consignments.
    ///
    /// Runs the two-phase validation: Phase 1 (`validate_deterministic`) collects pending external
    /// anchors (EVM mint events); the caller resolves them via `anchor_resolver` (return
    /// `true` to mark an anchor resolved); Phase 2 (`finalize_with_resolver`) checks that all
    /// anchors were resolved before returning the validated consignment.
    pub fn validate_bfa<F>(
        self,
        rules: &SchemaRules,
        resolver: &impl ResolveWitness,
        validation_config: &ValidationConfig,
        mut anchor_resolver: F,
    ) -> Result<ValidConsignment<TRANSFER>, ValidationError>
    where
        F: FnMut(&ExternalAnchor) -> bool,
    {
        if self.transfer != TRANSFER {
            return Err(ValidationError::InvalidConsignment(Failure::Custom(s!(
                "invalid consignment type"
            ))));
        }

        let mut validator =
            Validator::<FilteredContractState<UnfilteredContractState>, _>::validate_deterministic(
                &self,
                rules,
                (rules.schema(), self.contract_id()),
                validation_config,
            )?;

        let pending = validator.pending_external_anchors();
        for anchor in &pending {
            if anchor_resolver(anchor) {
                validator.record_anchor_resolution(anchor);
            }
        }

        let status = validator.finalize_with_resolver(resolver)?;

        Ok(ValidConsignment {
            validation_status: status,
            consignment: self,
        })
    }

    /// Modify a bundle in the consignment if it exists
    pub fn modify_bundle<F>(&mut self, witness_id: Txid, modifier: F) -> bool
    where F: Fn(&mut WitnessBundle) {
        let mut found = false;
        for bundle in self.bundles.iter_mut() {
            if bundle.witness_id() == witness_id {
                modifier(bundle);
                found = true;
            }
        }
        found
    }
}

impl<const TRANSFER: bool> StrictArmor for Consignment<TRANSFER> {
    type Id = ConsignmentId;
    const PLATE_TITLE: &'static str = "RGB CONSIGNMENT";

    fn armor_id(&self) -> Self::Id { self.commit_id() }
    fn armor_headers(&self) -> Vec<ArmorHeader> {
        let mut headers = vec![
            ArmorHeader::new(ASCII_ARMOR_VERSION, format!("{:#}", self.version)),
            ArmorHeader::new(
                ASCII_ARMOR_CONSIGNMENT_TYPE,
                if self.transfer { s!("transfer") } else { s!("contract") },
            ),
            ArmorHeader::new(ASCII_ARMOR_CONTRACT, self.contract_id().to_string()),
            ArmorHeader::new(ASCII_ARMOR_SCHEMA, self.schema_id().to_string()),
        ];
        if !self.terminals.is_empty() {
            headers.push(ArmorHeader::with(
                ASCII_ARMOR_TERMINAL,
                self.terminals.keys().map(BundleId::to_string),
            ));
        }
        headers
    }
}

// TODO: Remove after header-specific variants are added to StrictArmorError
#[derive(Debug, Display, Error, From)]
pub enum ConsignmentParseError {
    #[display(inner)]
    #[from]
    Armor(armor::StrictArmorError),

    #[display("required consignment type doesn't match the actual type")]
    Type,
}

impl<const TRANSFER: bool> FromStr for Consignment<TRANSFER> {
    type Err = ConsignmentParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let consignment = Self::from_ascii_armored_str(s)?;

        if consignment.transfer != TRANSFER {
            return Err(ConsignmentParseError::Type);
        }

        Ok(consignment)
    }
}

pub type UncheckedContract = UncheckedConsignment<false>;
pub type UncheckedTransfer = UncheckedConsignment<true>;

/// Error returned when a consignment fails the structural strict-encoding
/// constraint check performed by [`UncheckedConsignment::into_checked`].
#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ConsignmentConstraintError {
    /// consignment violates a strict-encoding constraint: {0}
    #[from]
    Serialize(SerializeError),

    /// consignment violates a strict-encoding constraint: {0}
    #[from]
    Deserialize(DeserializeError),

    /// consignment contains a value that violates a low-level type invariant.
    TypeInvariant,
}

/// A consignment parsed from an unvalidated representation whose structural
/// strict-encoding constraints have **not** yet been enforced.
///
/// Note this concerns *structural* constraints only. It is unrelated to the
/// full client-side validation performed by [`Consignment::validate`].
#[derive(Clone, Debug)]
pub struct UncheckedConsignment<const TRANSFER: bool>(Consignment<TRANSFER>);

impl<const TRANSFER: bool> UncheckedConsignment<TRANSFER> {
    /// Enforces the structural strict-encoding constraints and returns a
    /// [`Consignment`] guaranteed to satisfy every declared type-level
    /// invariant, or an error if any is violated.
    pub fn into_checked(self) -> Result<Consignment<TRANSFER>, ConsignmentConstraintError> {
        let consignment = self.0;
        // Round-trip through the strict codec. Encoding never rejects an
        // over-bound collection (it just writes its length), but decoding
        // re-imposes every declared bound, so an invariant-violating value is
        // rejected here instead of surviving.
        //
        // Encoding a value that violates a *bit-packed* small-integer invariant
        // (`u1`..`u7`) would panic inside the amplify codec, so we trap any
        // panic so a crafted input can never turn into a process abort.
        let encoded =
            catch_unwind(AssertUnwindSafe(|| consignment.to_strict_serialized::<{ usize::MAX }>()))
                .map_err(|_| ConsignmentConstraintError::TypeInvariant)?;
        let bytes = encoded?;
        let checked = Consignment::<TRANSFER>::from_strict_serialized::<{ usize::MAX }>(bytes)?;
        Ok(checked)
    }
}

impl<const TRANSFER: bool> From<Consignment<TRANSFER>> for UncheckedConsignment<TRANSFER> {
    fn from(consignment: Consignment<TRANSFER>) -> Self { Self(consignment) }
}

impl<const TRANSFER: bool> TryFrom<UncheckedConsignment<TRANSFER>> for Consignment<TRANSFER> {
    type Error = ConsignmentConstraintError;

    fn try_from(unchecked: UncheckedConsignment<TRANSFER>) -> Result<Self, Self::Error> {
        unchecked.into_checked()
    }
}

// serde ingestion for UncheckedConsignment. Consignment itself has no
// Deserialize, so the field-wise parsing is done by a shadow struct mirroring
// its layout. serde's remote attribute (which would avoid re-listing the
// construction) does not support the const-generic Consignment<TRANSFER> path,
// so we deserialize a non-generic shadow and re-wrap it into a Consignment of
// the requested kind.
#[cfg(feature = "serde")]
#[derive(Deserialize)]
#[serde(crate = "serde_crate", rename_all = "camelCase")]
struct ConsignmentShadow {
    version: ConsignmentVer,
    transfer: bool,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    terminals: SmallOrdMap<BundleId, TerminalSeals>,
    genesis: Genesis,
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    bundles: LargeVec<WitnessBundle>,
}

#[cfg(feature = "serde")]
impl<'de, const TRANSFER: bool> serde_crate::Deserialize<'de> for UncheckedConsignment<TRANSFER> {
    fn deserialize<D: serde_crate::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let shadow = ConsignmentShadow::deserialize(deserializer)?;
        Ok(UncheckedConsignment(Consignment {
            version: shadow.version,
            transfer: shadow.transfer,
            terminals: shadow.terminals,
            genesis: shadow.genesis,
            bundles: shadow.bundles,
        }))
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "serde")]
    use std::marker::PhantomData;

    use amplify::confinement::Confined;

    use super::*;
    #[cfg(feature = "serde")]
    use crate::containers::test_fixtures::almost_default_contract;

    #[test]
    fn contract_str_round_trip() {
        let s = include_str!("../../asset/armored_contract.default");
        let contract = Contract::from_str(s).unwrap();
        assert_eq!(contract.to_string(), s.replace('\r', ""), "contract string round trip fails");
    }

    #[test]
    fn consignment_strict_encode_round_trip() {
        let consignment = Consignment::<false>::strict_dumb();
        let bytes = consignment
            .to_strict_serialized::<{ usize::MAX }>()
            .unwrap();
        assert_eq!(bytes[0], 1, "consignment encoding must start with the V1 version byte");
        let decoded =
            Consignment::<false>::from_strict_serialized::<{ usize::MAX }>(bytes).unwrap();
        assert_eq!(decoded, consignment, "strict encode round trip fails");
    }

    #[test]
    fn strict_decode_rejects_v0() {
        // A V0 consignment is not representable in memory (`ConsignmentVer` has
        // no V0 variant), so V0 is rejected at the codec level: the version
        // byte is decoded through `try_from_u8`, which only accepts 1.
        let consignment = Consignment::<false>::strict_dumb();
        let mut bytes = consignment
            .to_strict_serialized::<{ usize::MAX }>()
            .unwrap()
            .release();
        assert_eq!(bytes[0], 1, "consignment must be encoded as version 1");

        bytes[0] = 0; // pretend this is a legacy V0 stream
        let res = Consignment::<false>::from_strict_serialized::<{ usize::MAX }>(
            Confined::try_from(bytes).unwrap(),
        );
        assert!(res.is_err(), "a V0 stream must not decode as a V1 consignment");
    }

    #[test]
    fn error_contract_strs() {
        Contract::from_str(include_str!("../../asset/armored_contract.default")).unwrap();

        // Wrong Id
        Contract::from_str(
            r#"-----BEGIN RGB CONSIGNMENT-----
Id: rgb:csg:aaaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa#guide-campus-arctic
Version: 2
Type: contract
Contract: rgb:qm7P!06T-uuBQT56-ovwOLzx-9Gka7Nb-84Nwo8g-blLb8kw
Schema: rgb:sch:CyqM42yAdM1moWyNZPQedAYt73BM$k9z$dKLUXY1voA#cello-global-deluxe
Check-SHA256: 181748dae0c83cbb44f6ccfdaddf6faca0bc4122a9f35fef47bab9aea023e4a1

0ssI2000000000000000000000000000000000000000000000000000000D0CRI`I$>^aZh38Qb#nj!
0000000000000000000000d59ZDjxe00000000dDb8~4rVQz13d2MfXa{vGU00000000000000000000
0000000000000

-----END RGB CONSIGNMENT-----"#,
        )
        .unwrap_err();

        // Wrong checksum
        Contract::from_str(
            r#"-----BEGIN RGB CONSIGNMENT-----
Id: rgb:csg:poAMvm9j-NdapxqA-MJ!5dwP-d!IIt2A-T!5OiXE-Tl54Yew#guide-campus-arctic
Version: 2
Type: contract
Contract: rgb:qm7P!06T-uuBQT56-ovwOLzx-9Gka7Nb-84Nwo8g-blLb8kw
Schema: rgb:sch:CyqM42yAdM1moWyNZPQedAYt73BM$k9z$dKLUXY1voA#cello-global-deluxe
Check-SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

0ssI2000000000000000000000000000000000000000000000000000000D0CRI`I$>^aZh38Qb#nj!
0000000000000000000000d59ZDjxe00000000dDb8~4rVQz13d2MfXa{vGU00000000000000000000
0000000000000

-----END RGB CONSIGNMENT-----"#,
        )
        .unwrap_err();
    }

    #[test]
    fn transfer_str_round_trip() {
        let s = include_str!("../../asset/armored_transfer.default");
        let transfer = Transfer::from_str(s).unwrap();
        assert_eq!(transfer.to_string(), s.replace('\r', ""), "transfer string round trip fails");
    }

    #[test]
    fn error_transfer_strs() {
        let s = include_str!("../../asset/armored_transfer.default");
        Transfer::from_str(s).unwrap();

        // Wrong Id
        Transfer::from_str(
            r#"-----BEGIN RGB CONSIGNMENT-----
Id: rgb:csg:aaaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa#guide-campus-arctic
Version: 2
Type: transfer
Contract: rgb:T24t0N1D-eiInTgb-BXlrrXz-$7OgV6n-WJWHPUD-BWNuqZw
Schema: rgb:sch:CyqM42yAdM1moWyNZPQedAYt73BM$k9z$dKLUXY1voA#cello-global-deluxe
Check-SHA256: 562a944631243e23a8de1d2aa2a5621be13351fc6f4d9aa8127c12ac4fb54d97

0s#O3000000000000000000000000000000000000000000000000000000D0CRI`I$>^aZh38Qb#nj!
0000000000000000000000d59ZDjxe00000000dDb8~4rVQz13d2MfXa{vGU00000000000000000000
0000000000000

-----END RGB CONSIGNMENT-----"#,
        )
        .unwrap_err();

        // Wrong checksum

        Transfer::from_str(
            r#"-----BEGIN RGB CONSIGNMENT-----
Id: rgb:csg:9jMKgkmP-alPghZC-bu65ctP-GT5tKgM-cAbaTLT-rhu8xQo#urban-athena-adam
Version: 2
Type: transfer
Contract: rgb:T24t0N1D-eiInTgb-BXlrrXz-$7OgV6n-WJWHPUD-BWNuqZw
Schema: rgb:sch:CyqM42yAdM1moWyNZPQedAYt73BM$k9z$dKLUXY1voA#cello-global-deluxe
Check-SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

0s#O3000000000000000000000000000000000000000000000000000000D0CRI`I$>^aZh38Qb#nj!
0000000000000000000000d59ZDjxe00000000dDb8~4rVQz13d2MfXa{vGU00000000000000000000
0000000000000

-----END RGB CONSIGNMENT-----"#,
        )
        .unwrap_err();

        // Wrong type
        assert!(matches!(
            Transfer::from_str(include_str!("../../asset/armored_contract.default")),
            Err(ConsignmentParseError::Type)
        ));
    }

    /// Verifies that V1 strict encoding and commit ID are stable across refactors.
    ///
    /// Run after any change that touches serialization or commitment logic to
    /// confirm V1 compatibility is intact.
    ///
    /// Prerequisites: run `test_fixtures::generate_v1_golden` (or
    /// `test_fixtures::regenerate_fixtures`)
    /// first and commit the asset files.
    #[test]
    fn v1_wire_stability() {
        let dir = env!("CARGO_MANIFEST_DIR");

        let golden_bytes = std::fs::read(format!("{dir}/asset/contract_golden.bin"))
            .expect("missing golden; run: cargo test -p rgb-ops generate_v1_golden -- --ignored");
        let golden_id = std::fs::read_to_string(format!("{dir}/asset/contract_golden_id.txt"))
            .expect("missing golden; run: cargo test -p rgb-ops generate_v1_golden -- --ignored");
        let golden_id = golden_id.trim();

        let contract =
            Contract::from_str(include_str!("../../asset/armored_contract.default")).unwrap();

        let bytes = contract.to_strict_serialized::<{ usize::MAX }>().unwrap();
        assert_eq!(bytes.as_slice(), golden_bytes.as_slice(), "V1 strict encoding changed");

        let commit_id = contract.consignment_id().to_string();
        assert_eq!(commit_id, golden_id, "V1 commit ID changed");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn v1_json_round_trip() {
        let contract = almost_default_contract();

        let json = serde_json::to_string(&contract).unwrap();
        let json_val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(json_val.get("types").is_none(), "V1 JSON must not include types field");
        assert!(json_val.get("schema").is_none(), "V1 JSON must not include schema field");
        assert!(json_val.get("scripts").is_none(), "V1 JSON must not include scripts field");
        assert_eq!(json_val["version"], serde_json::json!("v1"));

        let roundtripped = serde_json::from_str::<UncheckedContract>(&json)
            .unwrap()
            .into_checked()
            .unwrap();
        assert_eq!(roundtripped, contract, "V1 JSON round trip fails");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn v1_json_rejects_v0_version() {
        let contract = almost_default_contract();

        let mut json_val: serde_json::Value = serde_json::to_value(&contract).unwrap();
        json_val["version"] = serde_json::json!("v0");
        let json = serde_json::to_string(&json_val).unwrap();
        let result = serde_json::from_str::<UncheckedContract>(&json);
        assert!(result.is_err(), "V0 JSON should fail to deserialize as a V1 consignment");
    }

    /// `Consignment` must not be reachable through serde: deserializing one
    /// directly would skip [`UncheckedConsignment::into_checked`] and let a
    /// value violating a `Confined` bound through (`Confined` derives a
    /// passthrough `Deserialize` that does not re-check its length bounds).
    #[cfg(feature = "serde")]
    #[test]
    fn consignment_has_no_deserialize_impl() {
        struct Probe<T>(PhantomData<T>);

        impl<T> Probe<T> {
            fn new() -> Self { Probe(PhantomData) }
        }

        impl<T: for<'de> serde_crate::Deserialize<'de>> Probe<T> {
            fn has_deserialize(&self) -> bool { true }
        }

        trait NoDeserialize {
            fn has_deserialize(&self) -> bool { false }
        }
        impl<T> NoDeserialize for Probe<T> {}

        assert!(
            !Probe::<Contract>::new().has_deserialize(),
            "Consignment must not implement Deserialize: it would bypass into_checked"
        );
        assert!(
            !Probe::<Transfer>::new().has_deserialize(),
            "Consignment must not implement Deserialize: it would bypass into_checked"
        );
        // the sanctioned entry points do implement it
        assert!(Probe::<UncheckedContract>::new().has_deserialize());
        assert!(Probe::<UncheckedTransfer>::new().has_deserialize());
    }
}
