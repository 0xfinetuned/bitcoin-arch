use anyhow::anyhow;
use bech32::Fe32;

// TODO(chinonso): update with the actual values
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 0;
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5;
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111;
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196;

#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BitcoinNetwork {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

#[derive(Debug, Clone)]
pub enum Payload {
    PubkeyHash(Vec<u8>),
    ScriptHash(Vec<u8>),
    WitnessProgram(WitnessProgram),
}

impl Payload {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Payload::PubkeyHash(ph) => ph.clone(),
            Payload::ScriptHash(sh) => sh.clone(),
            Payload::WitnessProgram(wp) => wp.data.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WitnessProgram {
    pub version: WitnessVersion,
    pub data: Vec<u8>,
}

impl WitnessProgram {
    pub fn new(version: WitnessVersion, data: Vec<u8>) -> WitnessProgram {
        WitnessProgram { version, data }
    }
}

#[derive(Debug, Clone)]
pub enum WitnessVersion {
    V0,
    V1,
}

impl WitnessVersion {
    pub fn from_fe32(val: Fe32) -> Self {
        match val.to_u8() {
            0 => WitnessVersion::V0,
            1 => WitnessVersion::V1,
            _ => panic!("invalid witness script"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScriptPubkey(Vec<u8>);

impl ScriptPubkey {
    pub fn new(value: &[u8]) -> Self {
        Self(value.to_vec())
    }

    pub fn value(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn to_hex(&self) -> anyhow::Result<String> {
        match std::str::from_utf8(&self.0) {
            Ok(s) => Ok(s.to_string()),
            Err(err) => Err(anyhow!("utf8 sequence error: {:?}", err)),
        }
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
