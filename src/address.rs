use crate::types;
use crate::types::BitcoinNetwork;
use crate::types::{Payload, PubkeyHash, ScriptHash, ScriptPubkey, ScriptTypes};
use crate::utils::get_script_type;
use opcodes::all::*;
use std::io::{Error, ErrorKind};
use std::str::FromStr;

pub struct BitcoinAddress {
    pub network: BitcoinNetwork,
    pub payload: Vec<u8>,
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
                payload: data,
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
            types::PUBKEY_ADDRESS_PREFIX_TEST_M | types::PUBKEY_ADDRESS_PREFIX_TEST_N => (
                BitcoinNetwork::Testnet,
                Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()),
            ),
            types::SCRIPT_ADDRESS_PREFIX_TEST => (
                BitcoinNetwork::Testnet,
                Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()),
            ),
            _ => panic!("base58 invalid address version"),
        };

        Ok(BitcoinAddress {
            network,
            payload: payload.to_vec(),
        })
    }
}

impl BitcoinAddress {
    pub fn to_p2pkh_script(&self) -> Result<ScriptPubkey, Error> {
        let res = std::str::from_utf8(&self.payload[..]);
        match res {
            Ok(pkh_str) => Ok(ScriptPubkey::new(
                format!(
                    "{:x?}{:x?}{:x?}{}{:x?}{:x?}",
                    OP_DUP.to_u8(),
                    OP_HASH160.to_u8(),
                    OP_PUSHBYTES_20.to_u8(),
                    pkh_str,
                    OP_EQUALVERIFY.to_u8(),
                    OP_CHECKSIG.to_u8()
                )
                .as_bytes(),
            )),
            Err(_) => Err(Error::new(ErrorKind::InvalidData, "invalid pubkey hash")),
        }
    }

    pub fn to_p2sh_script(&self) -> Result<ScriptPubkey, Error> {
        let res = std::str::from_utf8(&self.payload[..]);
        match res {
            Ok(sh_str) => Ok(ScriptPubkey::new(
                format!(
                    "{:x?}{:x?}{}{:x?}",
                    OP_HASH160.to_u8(),
                    OP_PUSHBYTES_20.to_u8(),
                    sh_str,
                    OP_EQUAL.to_u8()
                )
                .as_bytes(),
            )),
            Err(_) => Err(Error::new(ErrorKind::InvalidData, "invalid script hash")),
        }
    }

    pub fn to_p2wpkh_script(&self) -> Result<ScriptPubkey, Error> {
        let res = std::str::from_utf8(&self.payload[..]);
        match res {
            Ok(pkh_str) => Ok(ScriptPubkey::new(
                format!("00{:x?}{}", OP_PUSHBYTES_20.to_u8(), pkh_str,).as_bytes(),
            )),
            Err(_) => Err(Error::new(ErrorKind::InvalidData, "invalid pubkey hash")),
        }
    }

    pub fn to_p2wsh_script(&self) -> Result<ScriptPubkey, Error> {
        let res = std::str::from_utf8(&self.payload[..]);
        match res {
            Ok(sh_str) => Ok(ScriptPubkey::new(
                format!("00{:x?}{}", OP_PUSHBYTES_32.to_u8(), sh_str,).as_bytes(),
            )),
            Err(_) => Err(Error::new(ErrorKind::InvalidData, "invalid script hash")),
        }
    }

    pub fn to_op_return_script(&self) -> Result<ScriptPubkey, Error> {
        let res = std::str::from_utf8(&self.payload[..]);
        match res {
            Ok(s) => Ok(ScriptPubkey::new(
                format!("{:x?}{}", OP_RETURN.to_u8(), s,).as_bytes(),
            )),
            Err(_) => Err(Error::new(
                ErrorKind::InvalidData,
                "invalid OP_RETURN script hash",
            )),
        }
    }

    pub fn from_script(spk: ScriptPubkey, network: BitcoinNetwork) -> Result<Self, Error> {
        let script_type = get_script_type(&spk.value())?;
        let payload = match script_type {
            ScriptTypes::P2PKH => Some(spk.value()[6..46].to_vec()),
            ScriptTypes::P2SH => Some(spk.value()[4..44].to_vec()),
            ScriptTypes::OPReturn => None,
            ScriptTypes::P2WPKH | ScriptTypes::P2WSH => Some(spk.value()[4..].to_vec()),
            _ => None,
        };

        Ok(BitcoinAddress {
            network,
            // TODO(chinonso): is it okay to return empty data for OP_RETURN?
            payload: payload.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::address::BitcoinAddress;
    use crate::types::BitcoinNetwork;

    #[test]
    fn bitcoin_address_to_p2pkh_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: b"55ae51684c43435da751ac8d2173b2652eb64105".to_vec(),
        };

        let script = bitcoin_address.to_p2pkh_script();
        assert!(script.is_ok());
        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"76a91455ae51684c43435da751ac8d2173b2652eb6410588ac"
        );

        let ba = BitcoinAddress::from_script(script, BitcoinNetwork::Bitcoin);
        assert!(ba.is_ok());
        let ba = ba.unwrap();
        assert_eq!(
            ba.payload,
            b"55ae51684c43435da751ac8d2173b2652eb64105".to_vec()
        )
    }

    #[test]
    fn bitcoin_address_to_p2sh_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: b"748284390f9e263a4b766a75d0633c50426eb875".to_vec(),
        };

        let script = bitcoin_address.to_p2sh_script();
        assert!(script.is_ok());
        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"a914748284390f9e263a4b766a75d0633c50426eb87587"
        );

        let ba = BitcoinAddress::from_script(script, BitcoinNetwork::Bitcoin);
        assert!(ba.is_ok());
        let ba = ba.unwrap();
        assert_eq!(
            ba.payload,
            b"748284390f9e263a4b766a75d0633c50426eb875".to_vec()
        )
    }

    #[test]
    fn bitcoin_address_to_p2wpkh_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: b"853ec3166860371ee67b7754ff85e13d7a0d6698".to_vec(),
        };

        let script = bitcoin_address.to_p2wpkh_script();
        assert!(script.is_ok());
        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"0014853ec3166860371ee67b7754ff85e13d7a0d6698"
        );

        let ba = BitcoinAddress::from_script(script, BitcoinNetwork::Bitcoin);
        assert!(ba.is_ok());
        let ba = ba.unwrap();
        assert_eq!(
            ba.payload,
            b"853ec3166860371ee67b7754ff85e13d7a0d6698".to_vec()
        )
    }

    #[test]
    fn bitcoin_address_to_p2wsh_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: b"65f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3".to_vec(),
        };

        let script = bitcoin_address.to_p2wsh_script();
        assert!(script.is_ok());
        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"002065f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3"
        );

        let ba = BitcoinAddress::from_script(script, BitcoinNetwork::Bitcoin);
        assert!(ba.is_ok());
        let ba = ba.unwrap();
        assert_eq!(
            ba.payload,
            b"65f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3".to_vec()
        )
    }

    #[test]
    fn bitcoin_address_to_op_return_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: b"0b68656c6c6f20776f726c64".to_vec(),
        };

        let script = bitcoin_address.to_op_return_script();
        assert!(script.is_ok());
        let script = script.unwrap();
        assert_eq!(script.value(), b"6a0b68656c6c6f20776f726c64");

        let ba = BitcoinAddress::from_script(script, BitcoinNetwork::Bitcoin);
        assert!(ba.is_ok());
        let ba = ba.unwrap();
        assert_eq!(ba.payload, vec![])
    }
}
