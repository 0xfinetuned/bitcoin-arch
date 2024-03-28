use bech32::Fe32;

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
}

pub enum ScriptTypes {
    P2PKH,
    P2SH,
    OPReturn,
    P2WPKH,
    P2WSH,
    P2TR,
}
