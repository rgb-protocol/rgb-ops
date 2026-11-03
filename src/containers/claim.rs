// RGB ops library for smart contracts on Bitcoin & Lightning network
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

//! Resolution of [`Claim`]s against the bridge they refer to.
//!
//! Consensus knows nothing about the chain the bridge lives on, so it can only take the caller's
//! word that a claim was confirmed. The contract however commits to a [`BridgeLocation`], which is
//! what makes it possible to check here that the resolver giving that word is connected to the
//! right chain. Where that commitment lives is defined by the schema, so extracting it is left to
//! the caller.

use std::str::FromStr;

use amplify::hex::{FromHex, ToHex};
use amplify::{hex, Bytes32};
use rgb::commit_verify::{CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use rgb::validation::{Claim, ValidationError};
use rgb::{OpId, Txid};

use crate::stl::{BridgeLocation, EvmContract};
use crate::LIB_NAME_RGB_OPS;

/// Id a bridge records a [`Claim::Lock`] under.
///
/// It is the tagged SHA-256, with tag `urn:lnp-bp:rgb:lock#2026-11-04`, of the strict encoding of
/// the operation id and the witness transaction id, i.e. their 32 bytes each, the latter in
/// internal byte order (reversed compared to the hex block explorers show):
///
/// `SHA256(t || t || opid || txid)`, where `t = SHA256(tag)`.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_hex)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct LockId(
    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::byte_array"))]
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitmentId for LockId {
    const TAG: &'static str = "urn:lnp-bp:rgb:lock#2026-11-04";
}

impl From<Sha256> for LockId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl LockId {
    /// Id of the lock for operation `opid` in witness transaction `witness_id`.
    pub fn with(opid: OpId, witness_id: Txid) -> Self {
        LockCommitment { opid, witness_id }.commit_id()
    }
}

/// What a [`LockId`] commits to.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_OPS)]
struct LockCommitment {
    opid: OpId,
    witness_id: Txid,
}

impl CommitEncode for LockCommitment {
    type CommitmentId = LockId;

    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_serialized(self); }
}

impl From<&Claim> for LockId {
    fn from(claim: &Claim) -> Self {
        let Claim::Lock {
            opid, witness_id, ..
        } = claim;
        Self::with(*opid, *witness_id)
    }
}

impl FromStr for LockId {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
}

/// Error resolving a claim.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ClaimResolverError {
    /// resolver is for chain ID {actual}, while the bridge lives on chain ID {expected}
    WrongChainId { expected: u64, actual: u64 },
    /// claim of operation {0} is not confirmed by the bridge
    Unconfirmed(OpId),
    /// unable to retrieve information from the resolver, {0}
    ResolverIssue(String),
    #[from]
    #[display(inner)]
    Validation(ValidationError),
}

/// Trait to confirm [`Claim`]s on the chain a bridge lives on.
pub trait ResolveClaim {
    /// EIP-155 chain ID of the EVM chain this resolver is connected to, as the node itself
    /// reports it (`eth_chainId`) rather than as configured.
    fn evm_chain_id(&self) -> Result<u64, ClaimResolverError>;

    /// Whether the bridge at `location` holds the lock `claim` refers to.
    ///
    /// The bridge must hold a lock for the claim's [`LockId`], which commits to its `opid` and
    /// `witness_id`, of exactly the claim's `amount`, and recorded before block `before_block`.
    /// Every field of the claim must match, otherwise bridge guarantees may break.
    ///
    /// How deep in the bridge's chain the lock must be to count as confirmed is up to the
    /// implementation, just as the finality of witnesses is up to a [`ResolveWitness`]: the right
    /// depth depends on the chain and on the risk the caller is willing to take. A lock that is
    /// not deep enough yet should be reported as not confirmed rather than as an error.
    ///
    /// [`ResolveWitness`]: rgb::validation::ResolveWitness
    fn is_confirmed(
        &self,
        location: &BridgeLocation,
        claim: &Claim,
    ) -> Result<bool, ClaimResolverError>;
}

impl<T: ResolveClaim> ResolveClaim for &T {
    fn evm_chain_id(&self) -> Result<u64, ClaimResolverError> { ResolveClaim::evm_chain_id(*self) }

    fn is_confirmed(
        &self,
        location: &BridgeLocation,
        claim: &Claim,
    ) -> Result<bool, ClaimResolverError> {
        ResolveClaim::is_confirmed(*self, location, claim)
    }
}

/// A resolver checked against the [`BridgeLocation`] the contract commits to.
///
/// Only [`Self::with`] hands one out, so a claim cannot be checked on a resolver nobody
/// checked.
pub struct CheckedClaimResolver<R: ResolveClaim> {
    inner: R,
    location: BridgeLocation,
}

impl<R: ResolveClaim> CheckedClaimResolver<R> {
    /// Checks that `inner` is connected to the chain the bridge at `location` lives on.
    ///
    /// The counterpart of [`PendingValidation::check_resolver`] for claims: a network
    /// round-trip on real nodes, so call it once per resolver.
    ///
    /// [`PendingValidation::check_resolver`]: rgb::validation::PendingValidation::check_resolver
    pub fn with(inner: R, location: BridgeLocation) -> Result<Self, ClaimResolverError> {
        match location {
            BridgeLocation::Evm(EvmContract { chain_id, .. }) => {
                let actual = inner.evm_chain_id()?;
                if actual != chain_id {
                    return Err(ClaimResolverError::WrongChainId {
                        expected: chain_id,
                        actual,
                    });
                }
            }
        }
        Ok(Self { inner, location })
    }

    /// The bridge location the resolver was checked against.
    pub fn location(&self) -> &BridgeLocation { &self.location }

    /// Asks the resolver whether `claim` is confirmed at the checked location.
    pub fn is_confirmed(&self, claim: &Claim) -> Result<bool, ClaimResolverError> {
        self.inner.is_confirmed(&self.location, claim)
    }
}

#[cfg(test)]
mod test {
    use rgb::bitcoin::hashes::Hash;

    use super::*;
    use crate::stl::EvmAddress;

    struct Resolver(u64);

    impl ResolveClaim for Resolver {
        fn evm_chain_id(&self) -> Result<u64, ClaimResolverError> { Ok(self.0) }

        fn is_confirmed(
            &self,
            _location: &BridgeLocation,
            _claim: &Claim,
        ) -> Result<bool, ClaimResolverError> {
            Ok(true)
        }
    }

    fn location(chain_id: u64) -> BridgeLocation {
        BridgeLocation::Evm(EvmContract {
            chain_id,
            address: EvmAddress::default(),
        })
    }

    #[test]
    fn lock_id_vectors() {
        let opid = OpId::from(core::array::from_fn::<u8, 32, _>(|i| i as u8));
        let txid = Txid::from_byte_array(core::array::from_fn(|i| 32 + i as u8));
        // the txid in the order block explorers show it is reversed
        assert_eq!(
            txid,
            Txid::from_str("3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120")
                .unwrap()
        );
        let lock_id = LockId::with(opid, txid);
        assert_eq!(
            lock_id.to_string(),
            "1ce683c92fdfb3ef54e39c7b461e731dad02cd240b366441f34a2c2e849a9876"
        );
        assert_eq!(LockId::from_str(&lock_id.to_string()).unwrap(), lock_id);

        assert_eq!(
            LockId::with(OpId::from([0u8; 32]), Txid::from_byte_array([0u8; 32])).to_string(),
            "9b30b6d0fcafbb02dea72ca6f0a1829fe643dfc3ea394df702d96688ff3906a9"
        );
    }

    #[test]
    fn lock_id_of_claim() {
        let opid = OpId::from([1u8; 32]);
        let witness_id = Txid::from_byte_array([2u8; 32]);
        let claim = Claim::Lock {
            opid,
            witness_id,
            amount: 1000,
            before_block: 20_000_000,
        };
        assert_eq!(LockId::from(&claim), LockId::with(opid, witness_id));
    }

    #[test]
    fn resolver_chain_id_is_checked() {
        assert!(CheckedClaimResolver::with(&Resolver(1), location(1)).is_ok());
        assert_eq!(
            CheckedClaimResolver::with(&Resolver(137), location(1)).err(),
            Some(ClaimResolverError::WrongChainId {
                expected: 1,
                actual: 137
            })
        );
    }
}
