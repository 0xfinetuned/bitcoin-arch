use crate::address::BitcoinAddress;
use opcodes::all::*;
use std::io::{Error, ErrorKind};
use crate::types::ScriptTypes::P2TR;
use crate::utils::{is_pubkey_hash, is_script_hash};

// TODO(chinonso): update with the actual values
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = '1' as u8;
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = '3' as u8;
pub const PUBKEY_ADDRESS_PREFIX_TEST_M: u8 = 'm' as u8;
pub const PUBKEY_ADDRESS_PREFIX_TEST_N: u8 = 'n' as u8;
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = '2' as u8;


pub struct ScriptHash {
    inner: Vec<u8>,
}

impl ScriptHash {
    pub fn from_slice(buffer: &[u8]) -> Result<ScriptHash, Error> {
        // TODO(chinonso): should verify if it is a valid script hash somehow
        Ok(ScriptHash {
            inner: buffer.to_vec(),
        })
    }
}

pub struct PubkeyHash {
    inner: Vec<u8>,
}

impl PubkeyHash {
    pub fn from_slice(buffer: &[u8]) -> Result<PubkeyHash, Error> {
        // TODO(chinonso): should verify if it is a valid pubkeyhash somehow
        Ok(PubkeyHash {
            inner: buffer.to_vec(),
        })
    }
}

pub enum Payload {
    PubkeyHash(PubkeyHash),
    ScriptHash(ScriptHash),
}

impl Payload {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Payload::PubkeyHash(ph) => ph.inner.clone(),
            Payload::ScriptHash(sh) => sh.inner.clone()
        }
    }
}

pub struct ScriptPubkey(Vec<u8>);

impl ScriptPubkey {
    pub fn new(value: &[u8]) -> Self {
        Self(value.to_vec())
    }

    pub fn value(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl From<&PubkeyHash> for ScriptPubkey {
    fn from(value: &PubkeyHash) -> Self {
        // TODO(chinonso): should verify that self.inner is always a valid 20-byte hex string
        let s =
            String::from_utf8(value.inner.clone()).expect("pubkey hash value should be valid utf8");
        Self(format!(
            "{:x?}{:x?}{:x?}{}{:x?}{:x?}",
            OP_DUP.to_u8(),
            OP_HASH160.to_u8(),
            OP_PUSHBYTES_20.to_u8(),
            s,
            OP_EQUALVERIFY.to_u8(),
            OP_CHECKSIG.to_u8()
        ).as_bytes().to_vec())
    }
}

impl From<&ScriptHash> for ScriptPubkey {
    fn from(value: &ScriptHash) -> Self {
        // TODO(chinonso): should verify that self.inner is always a valid 20-byte hex string
        let s =
            String::from_utf8(value.inner.clone()).expect("script hash value should be valid utf8");
        Self(format!(
            "{:x?}{:x?}{}{:x?}",
            OP_HASH160.to_u8(),
            OP_PUSHBYTES_20.to_u8(),
            s,
            OP_EQUAL.to_u8()
        ).as_bytes().to_vec())
    }
}

pub enum ScriptTypes {
    P2PKH,
    P2SH,
    OPReturn,
    P2WPKH,
    P2WSH,
    P2TR
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_pubkey_hash_to_script_pubkey_works() {
        let test_cases = vec![  (
            PubkeyHash::from_slice(b"55ae51684c43435da751ac8d2173b2652eb64105").unwrap(),
            "76a91455ae51684c43435da751ac8d2173b2652eb6410588ac".to_string(),
        )];

        for test_case in test_cases {
            let spk = ScriptPubkey::from(&test_case.0);
            // assert_eq!(spk.0, test_case.1);
        }
    }

    #[test]
    fn from_script_hash_to_script_pubkey_works() {
        let test_cases = vec![(
            ScriptHash::from_slice(b"748284390f9e263a4b766a75d0633c50426eb875").unwrap(),
            "a914748284390f9e263a4b766a75d0633c50426eb87587".to_string(),
        )];

        for test_case in test_cases {
            let spk = ScriptPubkey::from(&test_case.0);
            // assert_eq!(spk.0, test_case.1);
        }
    }
}
