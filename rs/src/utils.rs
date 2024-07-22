/*******************************************************************************
*   (c) 2018 - 2023 ZondaX AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#![deny(warnings, trivial_casts, trivial_numeric_casts)]
#![deny(unused_import_braces, unused_qualifications)]
#![deny(missing_docs)]

use std::error::Error;

const HARDENED: u32 = 0x80000000;

use crate::params::{ADDRESS_LEN, ED25519_PUBKEY_LEN, KEY_LENGTH, PK_LEN_PLUS_TAG, SALT_LEN, SIG_LEN_PLUS_TAG};
use byteorder::{LittleEndian, WriteBytesExt};

pub struct ResponseAddress {
    pub public_key: [u8; ED25519_PUBKEY_LEN + 1],
    pub address_bytes: [u8; ADDRESS_LEN],
    pub address_str: String,
}

/// NamadaApp wrapper signature Ed25519 -> 64  bytes
pub struct ResponseSignature {
    pub pubkey: [u8; PK_LEN_PLUS_TAG],
    pub raw_salt: [u8; SALT_LEN],
    pub raw_signature: [u8; SIG_LEN_PLUS_TAG],
    pub wrapper_salt: [u8; SALT_LEN],
    pub wrapper_signature: [u8; SIG_LEN_PLUS_TAG],
    pub raw_indices: Vec<u8>,
    pub wrapper_indices: Vec<u8>,
}

/// BIP44 Path
pub struct BIP44Path {
    /// BIP44 path in string format ("m/44'/283'/0/0/0")
    pub path: String,
}

impl BIP44Path {
    /**
    Serialize a [`BIP44Path`] in the format used in the app
     */
    pub fn serialize_path(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        if !self.path.starts_with('m') {
            return Err(
                "Path should start with \"m\" (e.g \"m/44'/5757'/5'/0/3\")".to_string().into(),
            );
        }

        let path_array: Vec<&str> = self.path.split('/').collect();
        if path_array.len() != 4 && path_array.len() != 6 {
            return Err("Invalid path. (e.g \"m/44'/134'/0/0/0\"".into());
        }

        let mut serialized_path = Vec::new();
        // First byte is path size
        serialized_path
            .write_u8((path_array.len() - 1) as u8)
            .unwrap();

        for mut child in path_array.iter().skip(1).copied() {
            let mut value = 0;
            if child.ends_with('\'') {
                value += HARDENED;
                child = &child[..child.len() - 1];
            }

            let child_number = child.parse::<u32>()?;
            if child_number >= HARDENED {
                return Err("Incorrect child value (bigger or equal to 0x80000000)".into());
            }

            value += child_number;
            serialized_path.write_u32::<LittleEndian>(value).unwrap();
        }

        Ok(serialized_path)
    }
}

/// Kinds of keys that can be requested in get keys instruction
#[derive(Copy, Clone)]
pub enum NamadaKeys {
    /// Public address request
    PublicAddress = 0x00,
    /// Viewing key request
    ViewKey = 0x01,
    /// Proof generation key request
    ProofGenerationKey = 0x02,
}

/// Kinds of data retrieval
pub enum P1Values {
    /// Request data without displaying it
    OnlyRetrieve = 0x00,
    /// Retrieve data whilst showing on screen
    ShowAddressInDevice = 0x01,
}

/// Response to the get keys instruction
pub enum KeyResponse {
    /// Address response
    Address {
        /// Public address
        public_address: [u8; KEY_LENGTH],
    },
    /// Viewing key responsee
    ViewKey {
        /// Viewing key
        view_key: [u8; KEY_LENGTH*2],
        /// Incoming viewing key
        ivk: [u8; KEY_LENGTH],
        /// Outgoing viewing key
        ovk: [u8; KEY_LENGTH],
    },
    /// Proof generation key response
    ProofGenKey {
        /// Spend authorization address key
        ak: [u8; KEY_LENGTH],
        /// Nullifier private key
        nsk: [u8; KEY_LENGTH],
    },
}


#[cfg(test)]
mod tests {
    use super::BIP44Path;

    #[test]
    fn bip44_serialization() {
        let path = BIP44Path {
            path: "m/44'/283'/0/0/0".to_string(),
        };
        let serialized_path = path.serialize_path().unwrap();
        println!("Serialized path: {:?}\n", serialized_path);

        assert_eq!(serialized_path.len(), 21);
        assert_eq!(
            hex::encode(&serialized_path),
            "052c0000801b010080000000000000000000000000"
        );
    }
}
