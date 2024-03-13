use std::io::Error;

// TODO(chinonso): update with the actual values
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = b'1';
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = b'3';
pub const PUBKEY_ADDRESS_PREFIX_TEST_M: u8 = b'm';
pub const PUBKEY_ADDRESS_PREFIX_TEST_N: u8 = b'n';
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = b'2';

#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BitcoinNetwork {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

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
            Payload::ScriptHash(sh) => sh.inner.clone(),
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

pub enum ScriptTypes {
    P2PKH,
    P2SH,
    OPReturn,
    P2WPKH,
    P2WSH,
    P2TR,
}
