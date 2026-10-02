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

//! Resolution of [`ExternalAnchor`]s against the chain the bridge lives on.
//!
//! Consensus knows nothing about that chain, so it can only take the caller's word that an
//! anchor was confirmed. The contract however commits to a [`BridgeLocation`], which is what
//! makes it possible to check here that the resolver giving that word is connected to the right
//! chain. Where that commitment lives is defined by the schema, so extracting it is left to the
//! caller.

use rgb::validation::{ExternalAnchor, ValidationError};
use rgb::OpId;

use crate::stl::{BridgeLocation, EvmContract};

/// Error resolving an external anchor.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AnchorResolverError {
    /// resolver is for chain ID {actual}, while the bridge lives on chain ID {expected}
    WrongChainId { expected: u64, actual: u64 },
    /// external anchor of operation {0} is not confirmed at the bridge location
    Unconfirmed(OpId),
    /// unable to retrieve information from the resolver, {0}
    ResolverIssue(String),
    #[from]
    #[display(inner)]
    Validation(ValidationError),
}

/// Trait to confirm [`ExternalAnchor`]s on the chain a bridge lives on.
pub trait ResolveAnchor {
    /// EIP-155 chain ID of the EVM chain this resolver is connected to, as the node itself
    /// reports it (`eth_chainId`) rather than as configured.
    fn evm_chain_id(&self) -> Result<u64, AnchorResolverError>;

    /// Whether `anchor` is confirmed by the bridge contract at `location`.
    fn is_confirmed(
        &self,
        location: &BridgeLocation,
        anchor: &ExternalAnchor,
    ) -> Result<bool, AnchorResolverError>;
}

impl<T: ResolveAnchor> ResolveAnchor for &T {
    fn evm_chain_id(&self) -> Result<u64, AnchorResolverError> {
        ResolveAnchor::evm_chain_id(*self)
    }

    fn is_confirmed(
        &self,
        location: &BridgeLocation,
        anchor: &ExternalAnchor,
    ) -> Result<bool, AnchorResolverError> {
        ResolveAnchor::is_confirmed(*self, location, anchor)
    }
}

/// A resolver checked against the [`BridgeLocation`] the contract commits to.
///
/// Only [`Self::with`] hands one out, so an anchor cannot be looked up on a resolver nobody
/// checked.
pub struct CheckedAnchorResolver<R: ResolveAnchor> {
    inner: R,
    location: BridgeLocation,
}

impl<R: ResolveAnchor> CheckedAnchorResolver<R> {
    /// Checks that `inner` is connected to the chain the bridge at `location` lives on.
    ///
    /// The counterpart of [`PendingValidation::check_resolver`] for external anchors: a network
    /// round-trip on real nodes, so call it once per resolver.
    ///
    /// [`PendingValidation::check_resolver`]: rgb::validation::PendingValidation::check_resolver
    pub fn with(inner: R, location: BridgeLocation) -> Result<Self, AnchorResolverError> {
        match location {
            BridgeLocation::Evm(EvmContract { chain_id, .. }) => {
                let actual = inner.evm_chain_id()?;
                if actual != chain_id {
                    return Err(AnchorResolverError::WrongChainId {
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

    /// Asks the resolver whether `anchor` is confirmed at the checked location.
    pub fn is_confirmed(&self, anchor: &ExternalAnchor) -> Result<bool, AnchorResolverError> {
        self.inner.is_confirmed(&self.location, anchor)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::stl::EvmAddress;

    struct Resolver(u64);

    impl ResolveAnchor for Resolver {
        fn evm_chain_id(&self) -> Result<u64, AnchorResolverError> { Ok(self.0) }

        fn is_confirmed(
            &self,
            _location: &BridgeLocation,
            _anchor: &ExternalAnchor,
        ) -> Result<bool, AnchorResolverError> {
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
    fn resolver_chain_id_is_checked() {
        assert!(CheckedAnchorResolver::with(&Resolver(1), location(1)).is_ok());
        assert_eq!(
            CheckedAnchorResolver::with(&Resolver(137), location(1)).err(),
            Some(AnchorResolverError::WrongChainId {
                expected: 1,
                actual: 137
            })
        );
    }
}
