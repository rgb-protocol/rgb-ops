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

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read, Write};

use amplify::confinement::U32 as FILE_MAX_LEN;
use armor::{AsciiArmor, StrictArmor};
use rgb::validation::SchemaDefinition;
#[cfg(all(feature = "fs", feature = "serde"))]
use strict_encoding::StrictReader;
use strict_encoding::{StreamReader, StreamWriter, StrictDecode, StrictEncode};

#[cfg(all(feature = "fs", feature = "serde"))]
use crate::containers::{Consignment, ValidConsignment};
use crate::containers::{Contract, Transfer};

const RGB_PREFIX: [u8; 4] = *b"RGB\x00";
pub(crate) const MAGIC_LEN: usize = 3;

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum LoadError {
    /// invalid file data.
    InvalidMagic,

    #[display(inner)]
    #[from]
    #[from(io::Error)]
    Decode(strict_encoding::DecodeError),

    #[display(inner)]
    #[from]
    Armor(armor::StrictArmorError),

    #[cfg(all(feature = "fs", feature = "serde"))]
    #[display(inner)]
    #[from]
    Json(serde_json::Error),
}

pub trait FileContent: StrictArmor {
    /// Magic bytes used in saving/restoring container from a file.
    const MAGIC: [u8; MAGIC_LEN];

    fn load(mut data: impl Read) -> Result<Self, LoadError> {
        let mut rgb = [0u8; 4];
        let mut magic = [0u8; MAGIC_LEN];
        data.read_exact(&mut rgb)?;
        data.read_exact(&mut magic)?;
        if rgb != RGB_PREFIX || magic != Self::MAGIC {
            return Err(LoadError::InvalidMagic);
        }

        let reader = StreamReader::new::<FILE_MAX_LEN>(data);
        let me = Self::strict_read(reader)?;

        Ok(me)
    }

    fn save(&self, mut writer: impl Write) -> Result<(), io::Error> {
        writer.write_all(&RGB_PREFIX)?;
        writer.write_all(&Self::MAGIC)?;

        let writer = StreamWriter::new::<FILE_MAX_LEN>(writer);
        self.strict_write(writer)?;

        Ok(())
    }

    #[cfg(feature = "fs")]
    fn load_file(path: impl AsRef<std::path::Path>) -> Result<Self, LoadError> {
        let file = std::fs::File::open(path)?;
        Self::load(file)
    }

    #[cfg(feature = "fs")]
    fn save_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), io::Error> {
        let file = std::fs::File::create(path)?;
        self.save(file)
    }

    #[cfg(feature = "fs")]
    fn load_armored(path: impl AsRef<std::path::Path>) -> Result<Self, LoadError> {
        let armor = std::fs::read_to_string(path)?;
        let content = Self::from_ascii_armored_str(&armor)?;
        Ok(content)
    }

    #[cfg(feature = "fs")]
    fn save_armored(&self, path: impl AsRef<std::path::Path>) -> Result<(), io::Error> {
        std::fs::write(path, self.to_ascii_armored_string())
    }
}

impl FileContent for SchemaDefinition {
    // Bumped from `SDF` when the definition started carrying strict type
    // libraries instead of nothing: a reader of the old layout must fail with
    // `InvalidMagic` rather than silently misparse the stream.
    const MAGIC: [u8; MAGIC_LEN] = *b"SD2";
}

impl FileContent for Contract {
    const MAGIC: [u8; MAGIC_LEN] = *b"CON";
}

impl FileContent for Transfer {
    const MAGIC: [u8; MAGIC_LEN] = *b"TFR";
}

#[cfg(all(feature = "fs", feature = "serde"))]
impl<const TRANSFER: bool> ValidConsignment<TRANSFER> {
    const VALID_MAGIC: [u8; MAGIC_LEN] = if TRANSFER { *b"VTF" } else { *b"VCO" };

    pub fn save_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), io::Error> {
        let mut file = std::fs::File::create(path)?;
        file.write_all(&RGB_PREFIX)?;
        file.write_all(&Self::VALID_MAGIC)?;

        let writer = StreamWriter::new::<FILE_MAX_LEN>(&mut file);
        StrictEncode::strict_write(&**self, writer)?;

        serde_json::to_writer(&mut file, self.validation_status()).map_err(io::Error::other)?;
        Ok(())
    }

    pub fn load_file(path: impl AsRef<std::path::Path>) -> Result<Self, LoadError> {
        let mut file = std::fs::File::open(path)?;
        let mut rgb = [0u8; 4];
        let mut magic = [0u8; MAGIC_LEN];
        file.read_exact(&mut rgb)?;
        file.read_exact(&mut magic)?;
        if rgb != RGB_PREFIX || magic != Self::VALID_MAGIC {
            return Err(LoadError::InvalidMagic);
        }

        let consignment = {
            let stream = StreamReader::new::<FILE_MAX_LEN>(&mut file);
            let mut reader = StrictReader::with(stream);
            Consignment::<TRANSFER>::strict_decode(&mut reader)?
        };

        let validation_status = serde_json::from_reader(&mut file)?;

        Ok(Self::from_parts(consignment, validation_status))
    }
}

// NB: only Serialize is derived, not Deserialize since it would bypass the
// structural bounds defined by the Confined trait.
#[derive(Clone, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub enum UniversalFile {
    #[from]
    SchemaDefinition(SchemaDefinition),

    #[from]
    Contract(Contract),

    #[from]
    Transfer(Transfer),
}

impl UniversalFile {
    pub fn load(mut data: impl Read) -> Result<Self, LoadError> {
        let mut rgb = [0u8; 4];
        let mut magic = [0u8; MAGIC_LEN];
        data.read_exact(&mut rgb)?;
        data.read_exact(&mut magic)?;
        if rgb != RGB_PREFIX {
            return Err(LoadError::InvalidMagic);
        }
        let mut reader = StreamReader::new::<FILE_MAX_LEN>(data);
        Ok(match magic {
            x if x == SchemaDefinition::MAGIC => SchemaDefinition::strict_read(&mut reader)?.into(),
            x if x == Contract::MAGIC => Contract::strict_read(&mut reader)?.into(),
            x if x == Transfer::MAGIC => Transfer::strict_read(&mut reader)?.into(),
            _ => return Err(LoadError::InvalidMagic),
        })
    }

    pub fn save(&self, mut writer: impl Write) -> Result<(), io::Error> {
        writer.write_all(&RGB_PREFIX)?;
        let magic = match self {
            UniversalFile::SchemaDefinition(_) => SchemaDefinition::MAGIC,
            UniversalFile::Contract(_) => Contract::MAGIC,
            UniversalFile::Transfer(_) => Transfer::MAGIC,
        };
        writer.write_all(&magic)?;

        let writer = StreamWriter::new::<FILE_MAX_LEN>(writer);

        match self {
            UniversalFile::SchemaDefinition(content) => content.strict_write(writer),
            UniversalFile::Contract(content) => content.strict_write(writer),
            UniversalFile::Transfer(content) => content.strict_write(writer),
        }
    }

    #[cfg(feature = "fs")]
    pub fn load_file(path: impl AsRef<std::path::Path>) -> Result<Self, LoadError> {
        let file = std::fs::File::open(path)?;
        Self::load(file)
    }

    #[cfg(feature = "fs")]
    pub fn save_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), io::Error> {
        let file = std::fs::File::create(path)?;
        self.save(file)
    }
}

impl Display for UniversalFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            UniversalFile::SchemaDefinition(content) => {
                Display::fmt(&content.display_ascii_armored(), f)
            }
            UniversalFile::Contract(content) => Display::fmt(&content.display_ascii_armored(), f),
            UniversalFile::Transfer(content) => Display::fmt(&content.display_ascii_armored(), f),
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::path::{Path, PathBuf};
    use std::{env, fs, process};

    #[cfg(all(feature = "fs", feature = "serde"))]
    use rgb::validation;
    use strict_encoding::StrictDumb;

    use super::*;
    use crate::containers::test_fixtures::almost_default_contract;
    #[cfg(feature = "fs")]
    use crate::containers::test_fixtures::almost_default_transfer;
    #[cfg(all(feature = "fs", feature = "serde"))]
    use crate::containers::ValidTransfer;

    // Committed golden files. Tests only ever *read* these: they pin the wire
    // format, so a test that rewrote one would be overwriting its own oracle.
    // Regenerate them with the `#[ignore]`d `regenerate_fixtures` /
    // `generate_v1_golden` in `test_fixtures`, then commit the result.
    static DEFAULT_SCHEMA_DEF_PATH: &str = "asset/schema_definition.default";
    #[cfg(feature = "fs")]
    static ARMORED_SCHEMA_DEF_PATH: &str = "asset/armored_schema_definition.default";

    static DEFAULT_CONTRACT_PATH: &str = "asset/contract.default";
    #[cfg(feature = "fs")]
    static ARMORED_CONTRACT_PATH: &str = "asset/armored_contract.default";

    #[cfg(feature = "fs")]
    static DEFAULT_TRANSFER_PATH: &str = "asset/transfer.default";
    #[cfg(feature = "fs")]
    static ARMORED_TRANSFER_PATH: &str = "asset/armored_transfer.default";

    #[cfg(all(feature = "fs", feature = "serde"))]
    static DEFAULT_VALID_TRANSFER_PATH: &str = "asset/valid_transfer.default";

    /// A scratch path under the system temp directory, removed on drop.
    ///
    /// Round-trip tests save through one of these rather than through the
    /// `asset/` goldens, so that saving is never aimed at a shared, committed
    /// file: two tests touching one path race each other, and a test that
    /// rewrites the fixture it also asserts against stops checking anything.
    struct TmpPath(PathBuf);

    impl TmpPath {
        fn new(name: &str) -> Self {
            // The pid separates concurrent `cargo test` processes; the
            // per-test `name` separates tests within one process.
            let path = env::temp_dir().join(format!("rgb-ops-test-{}-{name}", process::id()));
            let _ = fs::remove_file(&path);
            Self(path)
        }
    }

    impl AsRef<Path> for TmpPath {
        fn as_ref(&self) -> &Path { &self.0 }
    }

    impl Drop for TmpPath {
        fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
    }

    /// Asserts that the committed golden at `path` still decodes to `expected`.
    fn assert_golden<T: FileContent + PartialEq + Debug>(path: &str, expected: &T) {
        let file = File::open(path).unwrap_or_else(|e| panic!("fail to open {path}: {e}"));
        let loaded = T::load(file).unwrap_or_else(|e| panic!("fail to load {path}: {e}"));
        assert_eq!(&loaded, expected, "{path} no longer decodes to the expected value");
    }

    /// Asserts that `value` survives a save/load round trip through a scratch
    /// file named after the calling test.
    fn assert_round_trip<T: FileContent + PartialEq + Debug>(name: &str, value: &T) {
        let path = TmpPath::new(name);
        let file = File::create(&path).unwrap_or_else(|e| panic!("fail to create {name}: {e}"));
        value
            .save(file)
            .unwrap_or_else(|e| panic!("fail to save {name}: {e}"));

        let file = File::open(&path).unwrap_or_else(|e| panic!("fail to reopen {name}: {e}"));
        let loaded = T::load(file).unwrap_or_else(|e| panic!("fail to reload {name}: {e}"));
        assert_eq!(&loaded, value, "{name} does not survive a save/load round trip");
    }

    /// [`assert_golden`] for the ASCII-armored representation.
    #[cfg(feature = "fs")]
    fn assert_armored_golden<T: FileContent + PartialEq + Debug>(path: &str, expected: &T) {
        let loaded = T::load_armored(path).unwrap_or_else(|e| panic!("fail to load {path}: {e}"));
        assert_eq!(&loaded, expected, "{path} no longer decodes to the expected value");
    }

    /// [`assert_round_trip`] for the ASCII-armored representation.
    #[cfg(feature = "fs")]
    fn assert_armored_round_trip<T: FileContent + PartialEq + Debug>(name: &str, value: &T) {
        let path = TmpPath::new(name);
        value
            .save_armored(&path)
            .unwrap_or_else(|e| panic!("fail to save armored {name}: {e}"));
        let loaded =
            T::load_armored(&path).unwrap_or_else(|e| panic!("fail to reload armored {name}: {e}"));
        assert_eq!(&loaded, value, "{name} does not survive an armored round trip");
    }

    #[test]
    fn schema_definition_golden() {
        assert_golden(DEFAULT_SCHEMA_DEF_PATH, &SchemaDefinition::strict_dumb());
    }

    #[test]
    fn schema_definition_save_load_round_trip() {
        assert_round_trip("schema_definition", &SchemaDefinition::strict_dumb());
    }

    #[cfg(feature = "fs")]
    #[test]
    fn armored_schema_definition_golden() {
        assert_armored_golden(ARMORED_SCHEMA_DEF_PATH, &SchemaDefinition::strict_dumb());
    }

    #[cfg(feature = "fs")]
    #[test]
    fn armored_schema_definition_save_load_round_trip() {
        assert_armored_round_trip("armored_schema_definition", &SchemaDefinition::strict_dumb());
    }

    #[test]
    fn contract_golden() { assert_golden(DEFAULT_CONTRACT_PATH, &almost_default_contract()); }

    #[test]
    fn contract_save_load_round_trip() {
        assert_round_trip("contract", &almost_default_contract());
    }

    #[cfg(feature = "fs")]
    #[test]
    fn armored_contract_golden() {
        assert_armored_golden(ARMORED_CONTRACT_PATH, &almost_default_contract());
    }

    #[cfg(feature = "fs")]
    #[test]
    fn armored_contract_save_load_round_trip() {
        assert_armored_round_trip("armored_contract", &almost_default_contract());
    }

    #[cfg(feature = "fs")]
    #[test]
    fn transfer_golden() { assert_golden(DEFAULT_TRANSFER_PATH, &almost_default_transfer()); }

    #[cfg(feature = "fs")]
    #[test]
    fn transfer_save_load_round_trip() {
        assert_round_trip("transfer", &almost_default_transfer());
    }

    #[cfg(feature = "fs")]
    #[test]
    fn armored_transfer_golden() {
        assert_armored_golden(ARMORED_TRANSFER_PATH, &almost_default_transfer());
    }

    #[cfg(feature = "fs")]
    #[test]
    fn armored_transfer_save_load_round_trip() {
        assert_armored_round_trip("armored_transfer", &almost_default_transfer());
    }

    /// `ValidTransfer` gets its own pair rather than going through the helpers
    /// above: it carries a JSON validation status alongside the consignment,
    /// so it has its own `save_file`/`load_file` and no `PartialEq`.
    #[cfg(all(feature = "fs", feature = "serde"))]
    fn default_valid_transfer() -> ValidTransfer {
        ValidTransfer::from_parts(almost_default_transfer(), validation::Status::default())
    }

    #[cfg(all(feature = "fs", feature = "serde"))]
    #[test]
    fn valid_transfer_golden() {
        let loaded = ValidTransfer::load_file(DEFAULT_VALID_TRANSFER_PATH)
            .expect("fail to load valid_transfer.default");
        assert_eq!(
            loaded.into_consignment(),
            default_valid_transfer().into_consignment(),
            "{DEFAULT_VALID_TRANSFER_PATH} no longer decodes to the expected value"
        );
    }

    #[cfg(all(feature = "fs", feature = "serde"))]
    #[test]
    fn valid_transfer_save_load_round_trip() {
        let path = TmpPath::new("valid_transfer");
        let valid_transfer = default_valid_transfer();
        valid_transfer
            .save_file(&path)
            .expect("fail to save valid transfer");

        let loaded = ValidTransfer::load_file(&path).expect("fail to reload valid transfer");
        assert_eq!(
            loaded.into_consignment(),
            valid_transfer.into_consignment(),
            "valid transfer does not survive a save/load round trip"
        );
    }
}
