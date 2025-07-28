// RGB ops library for working with smart contracts on Bitcoin & Lightning
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

use bp::Txid;
use esplora::{BlockingClient, Config, Error};
use rgbcore::validation::{ResolveWitness, WitnessResolverError, WitnessStatus};
use rgbcore::ChainNet;

use crate::indexers::esplora_blocking::EsploraClient;

/// Wrapper of an esplora client, necessary to implement the foreign `ResolveWitness` trait.
/// It assumes that mempool.space exposes the same APIs as esplora.
// Currently, this client is wrapping an `crate::indexers::esplora_blocking::EsploraClient`
// instance. If the mempool service changes in the future and is not compatible with
// esplora::BlockingClient, only the internal implementation needs to be modified.
pub struct MemPoolClient {
    inner: EsploraClient,
}

impl MemPoolClient {
    /// Creates a new `MemPoolClient` instance.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the mempool server.
    /// * `config` - The configuration for the mempool client.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `MemPoolClient` instance if
    /// successful, or an `Error` if an error occurred.
    #[allow(clippy::result_large_err)]
    pub fn new(url: &str, config: Config) -> Result<Self, Error> {
        let inner = EsploraClient {
            inner: BlockingClient::from_config(url, config)?,
        };
        Ok(MemPoolClient { inner })
    }
}

impl ResolveWitness for MemPoolClient {
    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        self.inner.check_chain_net(chain_net)
    }

    fn resolve_witness(&self, txid: Txid) -> Result<WitnessStatus, WitnessResolverError> {
        self.inner.resolve_witness(txid)
    }
}

#[cfg(test)]
mod test {
    use esplora::Config;
    #[test]
    fn test_mempool_client_mainnet_tx() {
        let client = super::MemPoolClient::new("https://mempool.space/api", Config::default())
            .expect("Failed to create client");
        let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
            .parse()
            .unwrap();
        let status = client.inner.inner.tx_status(&txid).unwrap();
        assert_eq!(status.block_height, Some(0));
        assert_eq!(status.block_time, Some(1231006505));
    }

    #[test]
    fn test_mempool_client_testnet_tx() {
        let client =
            super::MemPoolClient::new("https://mempool.space/testnet/api", Config::default())
                .expect("Failed to create client");

        let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
            .parse()
            .unwrap();
        let status = client.inner.inner.tx_status(&txid).unwrap();
        assert_eq!(status.block_height, Some(0));
        assert_eq!(status.block_time, Some(1296688602));
    }

    #[test]
    fn test_mempool_client_testnet4_tx() {
        let client =
            super::MemPoolClient::new("https://mempool.space/testnet4/api", Config::default())
                .expect("Failed to create client");
        let txid = "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
            .parse()
            .unwrap();
        let status = client.inner.inner.tx_status(&txid).unwrap();
        assert_eq!(status.block_height, Some(0));
        assert_eq!(status.block_time, Some(1714777860));
    }

    #[test]
    fn test_mempool_client_testnet4_tx_detail() {
        let client =
            super::MemPoolClient::new("https://mempool.space/testnet4/api", Config::default())
                .expect("Failed to create client");
        let txid = "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
            .parse()
            .unwrap();
        let tx = client
            .inner
            .inner
            .tx(&txid)
            .expect("Failed to get tx")
            .expect("Tx not found");
        assert!(!tx.inputs.is_empty());
        assert!(!tx.outputs.is_empty());
        assert_eq!(tx.outputs[0].value, 5_000_000_000);
    }
}
