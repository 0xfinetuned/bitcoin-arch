use crate::types;
use crate::types::{BitcoinNetwork, WitnessProgram, WitnessVersion};
use crate::types::{Payload, ScriptPubkey, ScriptTypes};
use crate::utils::get_script_type;
use opcodes::all::*;
use std::io::{Error, ErrorKind};
use std::str::FromStr;

#[derive(Debug, Clone)]
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
            let (_hrp, version, data) = bech32::segwit::decode(s).unwrap();

            return Ok(BitcoinAddress {
                network,
                payload: Payload::WitnessProgram(WitnessProgram::new(
                    WitnessVersion::from_fe32(version),
                    data,
                )),
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
                Payload::PubkeyHash(data[1..].to_vec()),
            ),
            types::SCRIPT_ADDRESS_PREFIX_MAIN => (
                BitcoinNetwork::Bitcoin,
                Payload::ScriptHash(data[1..].to_vec()),
            ),
            types::PUBKEY_ADDRESS_PREFIX_TEST => (
                BitcoinNetwork::Testnet,
                Payload::PubkeyHash(data[1..].to_vec()),
            ),
            types::SCRIPT_ADDRESS_PREFIX_TEST => (
                BitcoinNetwork::Testnet,
                Payload::ScriptHash(data[1..].to_vec()),
            ),
            _ => panic!("base58 invalid address version"),
        };

        Ok(BitcoinAddress { network, payload })
    }
}

impl BitcoinAddress {
    pub fn to_script(&self) -> Result<ScriptPubkey, Error> {
        match &self.payload {
            Payload::PubkeyHash(data) => {
                return Ok(ScriptPubkey::new(
                    format!(
                        "{:x?}{:x?}{:x?}{}{:x?}{:x?}",
                        OP_DUP.to_u8(),
                        OP_HASH160.to_u8(),
                        OP_PUSHBYTES_20.to_u8(),
                        hex::encode(&data),
                        OP_EQUALVERIFY.to_u8(),
                        OP_CHECKSIG.to_u8()
                    )
                    .as_bytes(),
                ));
            }
            Payload::ScriptHash(data) => {
                return Ok(ScriptPubkey::new(
                    format!(
                        "{:x?}{:x?}{}{:x?}",
                        OP_HASH160.to_u8(),
                        OP_PUSHBYTES_20.to_u8(),
                        hex::encode(&data),
                        OP_EQUAL.to_u8()
                    )
                    .as_bytes(),
                ));
            }
            Payload::WitnessProgram(program) => {
                return match program.version {
                    WitnessVersion::V0 => {
                        let data = hex::encode(&program.data);
                        if data.len() == 40 {
                            return Ok(ScriptPubkey::new(
                                format!("00{:x?}{}", OP_PUSHBYTES_20.to_u8(), data,).as_bytes(),
                            ));
                        }
                        if data.len() == 64 {
                            return Ok(ScriptPubkey::new(
                                format!("00{:x?}{}", OP_PUSHBYTES_32.to_u8(), data,).as_bytes(),
                            ));
                        }
                        Err(Error::new(
                            ErrorKind::InvalidData,
                            "invalid witness program data",
                        ))
                    }
                    WitnessVersion::V1 => {
                        return Ok(ScriptPubkey::new(
                            format!(
                                "{:x?}{:x?}{}",
                                OP_PUSHNUM_1.to_u8(),
                                OP_PUSHBYTES_32.to_u8(),
                                hex::encode(&program.data)
                            )
                            .as_bytes(),
                        ));
                    }
                }
            }
        }
    }

    pub fn from_script(spk: ScriptPubkey, network: BitcoinNetwork) -> Result<Self, Error> {
        let script_type = get_script_type(&spk.value())?;
        let payload = match script_type {
            ScriptTypes::P2PKH => {
                let hex_str = spk.to_hex().unwrap();
                let data = hex::decode(&hex_str[6..46]).unwrap();
                Some(Payload::ScriptHash(data))
            }
            ScriptTypes::P2SH => {
                let hex_str = spk.to_hex().unwrap();
                let data = hex::decode(&hex_str[4..44]).unwrap();
                Some(Payload::ScriptHash(data))
            }
            ScriptTypes::P2WPKH | ScriptTypes::P2WSH => {
                let hex_str = spk.to_hex().unwrap();
                let data = hex::decode(&hex_str[4..]).unwrap();
                Some(Payload::WitnessProgram(WitnessProgram::new(
                    WitnessVersion::V0,
                    data,
                )))
            }
            ScriptTypes::P2TR => {
                let hex_str = spk.to_hex().unwrap();
                let data = hex::decode(&hex_str[4..]).unwrap();
                Some(Payload::WitnessProgram(WitnessProgram::new(
                    WitnessVersion::V1,
                    data,
                )))
            }
            ScriptTypes::OPReturn => None,
        };

        if payload.is_none() {
            return Err(Error::new(ErrorKind::InvalidData, "script type is invalid"));
        }

        Ok(BitcoinAddress {
            network,
            // TODO(chinonso): is it okay to return empty data for OP_RETURN?
            payload: payload.unwrap(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::address::BitcoinAddress;
    use crate::types::BitcoinNetwork;
    use std::str::FromStr;

    #[test]
    fn bitcoin_address_to_p2pkh_and_back() {
        let expected_btc_address =
            BitcoinAddress::from_str("mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt").unwrap();

        let script = expected_btc_address.to_script();
        assert!(script.is_ok());

        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"76a914344a0f48ca150ec2b903817660b9b68b13a6702688ac"
        );

        let actual_btc_address = BitcoinAddress::from_script(script, BitcoinNetwork::Testnet);

        assert!(actual_btc_address.is_ok());

        let actual_btc_address = actual_btc_address.unwrap();
        assert_eq!(
            actual_btc_address.payload.to_vec(),
            expected_btc_address.payload.to_vec(),
        )
    }

    #[test]
    fn bitcoin_address_to_p2sh_and_back() {
        let expected_btc_address =
            BitcoinAddress::from_str("2Mw3bN3ESQ8rNBRvT8vMwuRGtv1Sagnmx3K").unwrap();

        let script = expected_btc_address.to_script();
        assert!(script.is_ok());

        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"a91429ad5ac881228b62bf7ae509aa3d9971f3b786b587"
        );

        let actual_btc_address = BitcoinAddress::from_script(script, BitcoinNetwork::Testnet);

        assert!(actual_btc_address.is_ok());

        let actual_btc_address = actual_btc_address.unwrap();
        assert_eq!(
            actual_btc_address.payload.to_vec(),
            expected_btc_address.payload.to_vec(),
        )
    }

    #[test]
    fn bitcoin_address_to_p2wpkh_and_back() {
        let expected_btc_address =
            BitcoinAddress::from_str("tb1q0wd9zhh68uac6mxeyxrnjspaamfr4mu9apqluy").unwrap();

        let script = expected_btc_address.to_script();
        assert!(script.is_ok());

        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"00147b9a515efa3f3b8d6cd9218739403deed23aef85"
        );

        let actual_btc_address = BitcoinAddress::from_script(script, BitcoinNetwork::Testnet);

        assert!(actual_btc_address.is_ok());

        let actual_btc_address = actual_btc_address.unwrap();
        assert_eq!(
            actual_btc_address.payload.to_vec(),
            expected_btc_address.payload.to_vec(),
        )
    }

    #[test]
    fn bitcoin_address_to_p2wsh_and_back() {
        let expected_btc_address =
            BitcoinAddress::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7").unwrap();

        let script = expected_btc_address.to_script();
        assert!(script.is_ok());

        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
        );

        let actual_btc_address = BitcoinAddress::from_script(script, BitcoinNetwork::Testnet);

        assert!(actual_btc_address.is_ok());

        let actual_btc_address = actual_btc_address.unwrap();
        assert_eq!(
            actual_btc_address.payload.to_vec(),
            expected_btc_address.payload.to_vec(),
        )
    }

    #[test]
    fn bitcoin_address_to_p2tr_and_back() {
        let expected_btc_address = BitcoinAddress::from_str(
            "tb1plltrggq7p02uz8x7su2ajxzuhp05uvr5jv8tm49xumjkuceq84xqeynrkc",
        )
        .unwrap();

        let script = expected_btc_address.to_script();
        assert!(script.is_ok());

        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"5120ffd634201e0bd5c11cde8715d9185cb85f4e3074930ebdd4a6e6e56e63203d4c"
        );

        let actual_btc_address = BitcoinAddress::from_script(script, BitcoinNetwork::Testnet);

        assert!(actual_btc_address.is_ok());

        let actual_btc_address = actual_btc_address.unwrap();
        assert_eq!(
            actual_btc_address.payload.to_vec(),
            expected_btc_address.payload.to_vec(),
        )
    }
}
