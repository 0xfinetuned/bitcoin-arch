use crate::network::BitcoinNetwork;
use crate::types::{Payload, PubkeyHash, ScriptHash, ScriptPubkey};
use std::str::FromStr;
use crate::types;

pub struct BitcoinAddress {
    pub network: BitcoinNetwork,
    pub payload: Payload,
}

#[derive(Debug, Clone)]
pub struct ParseError;

fn find_bech32_prefix(bech32: &str) -> &str {
    // Split at the last occurrence of the separator character '1'.
    match bech32.rfind('1') {
        None => bech32,
        Some(sep) => bech32.split_at(sep).0,
    }
}

impl FromStr for BitcoinAddress {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bech32_network = match find_bech32_prefix(s) {
            "bc" | "BC" => Some(BitcoinNetwork::Bitcoin),
            "tb" | "TB" => Some(BitcoinNetwork::Testnet),
            "bcrt" | "BCRT" => Some(BitcoinNetwork::Regtest),
            _ => None,
        };
        if let Some(network) = bech32_network {
            let (_hrp, _version, data) = bech32::segwit::decode(s).unwrap();

            return Ok(BitcoinAddress {
                network,
                // TODO(chinonso): assume its a script hash for now, should change later
                payload: Payload::ScriptHash(ScriptHash::from_slice(&data).unwrap()),
            });
        }

        if s.len() > 50 {
            panic!("base58 invalid length")
        }
        let data = base58::decode_check(s).unwrap();
        if data.len() != 21 {
            panic!("base58 invalid length")
        }

        let (network, payload) = match data[0] {
            types::PUBKEY_ADDRESS_PREFIX_MAIN => (
                BitcoinNetwork::Bitcoin,
                Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()),
            ),
            types::SCRIPT_ADDRESS_PREFIX_MAIN => (
                BitcoinNetwork::Bitcoin,
                Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()),
            ),
            types::PUBKEY_ADDRESS_PREFIX_TEST => (
                BitcoinNetwork::Testnet,
                Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()),
            ),
            types::SCRIPT_ADDRESS_PREFIX_TEST => (
                BitcoinNetwork::Testnet,
                Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()),
            ),
            _ => panic!("base58 invalid address version"),
        };

        Ok(BitcoinAddress { network, payload })
    }
}

impl BitcoinAddress {
    pub fn to_script_pubkey(&self) -> ScriptPubkey {
        match &self.payload {
            Payload::PubkeyHash(ph) => ScriptPubkey::from(ph),
            Payload::ScriptHash(sh) => ScriptPubkey::from(sh),
        }
    }

    pub fn from_script_pubkey(spk: ScriptPubkey, network: BitcoinNetwork) -> Self {
        todo!()
    }
}

// impl From<ScriptPubkey> for BitcoinAddress {
//     fn from(value: ScriptPubkey) -> Self {
//         let value = value.value();
//     }
// }
