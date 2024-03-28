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
            types::PUBKEY_ADDRESS_PREFIX_TEST_M | types::PUBKEY_ADDRESS_PREFIX_TEST_N => (
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
                println!("AS HEX: {:?}", hex::encode(data));
                if let Ok(pkh_str) = std::str::from_utf8(data) {
                    println!("AS STRING: {:?}", pkh_str);
                    return Ok(ScriptPubkey::new(
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
                    ));
                }
                Err(Error::new(ErrorKind::InvalidData, "invalid pubkey hash"))
            }
            Payload::ScriptHash(data) => {
                // if let Ok(sh_str) = std::str::from_utf8(data) {
                //     return Ok(ScriptPubkey::new(
                //         format!(
                //             "{:x?}{:x?}{}{:x?}",
                //             OP_HASH160.to_u8(),
                //             OP_PUSHBYTES_20.to_u8(),
                //             sh_str,
                //             OP_EQUAL.to_u8()
                //         )
                //         .as_bytes(),
                //     ));
                // }
                // Err(Error::new(ErrorKind::InvalidData, "invalid script hash"))
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
                            format!("{:x?}{:x?}{}", OP_PUSHNUM_1.to_u8(), OP_PUSHBYTES_32.to_u8(), hex::encode(&program.data)).as_bytes(),
                        ));
                        // if let Ok(data) = std::str::from_utf8(&program.data) {
                        //     return Ok(ScriptPubkey::new(
                        //         format!("{:x?}{}", OP_PUSHBYTES_32.to_u8(), data).as_bytes(),
                        //     ));
                        // }
                        // return Err(Error::new(
                        //     ErrorKind::InvalidData,
                        //     "invalid witness program data",
                        // ));
                    }
                }
            }
        }
    }

    pub fn from_script(spk: ScriptPubkey, network: BitcoinNetwork) -> Result<Self, Error> {
        let script_type = get_script_type(&spk.value())?;
        let payload = match script_type {
            ScriptTypes::P2PKH => Some(Payload::PubkeyHash(spk.value()[6..46].to_vec())),
            ScriptTypes::P2SH => Some(Payload::ScriptHash(spk.value()[4..44].to_vec())),
            ScriptTypes::P2WPKH | ScriptTypes::P2WSH => Some(Payload::WitnessProgram(
                WitnessProgram::new(WitnessVersion::V0, spk.value()[4..].to_vec()),
            )),
            ScriptTypes::P2TR => Some(Payload::WitnessProgram(WitnessProgram::new(
                WitnessVersion::V1,
                spk.value()[2..].to_vec(),
            ))),
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
    use crate::types::{BitcoinNetwork, Payload, ScriptPubkey, WitnessProgram, WitnessVersion};
    use std::str::FromStr;

    #[test]
    fn bitcoin_address_to_p2pkh_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: Payload::PubkeyHash(b"55ae51684c43435da751ac8d2173b2652eb64105".to_vec()),
        };

        let script = bitcoin_address.to_script();
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
            ba.payload.to_vec(),
            b"55ae51684c43435da751ac8d2173b2652eb64105".to_vec()
        )
    }

    #[test]
    fn bitcoin_address_to_p2sh_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: Payload::ScriptHash(b"748284390f9e263a4b766a75d0633c50426eb875".to_vec()),
        };

        let script = bitcoin_address.to_script();
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
            ba.payload.to_vec(),
            b"748284390f9e263a4b766a75d0633c50426eb875".to_vec()
        )
    }

    #[test]
    fn bitcoin_address_to_p2wpkh_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: Payload::WitnessProgram(WitnessProgram::new(
                WitnessVersion::V0,
                b"853ec3166860371ee67b7754ff85e13d7a0d6698".to_vec(),
            )),
        };

        let script = bitcoin_address.to_script();
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
            ba.payload.to_vec(),
            b"853ec3166860371ee67b7754ff85e13d7a0d6698".to_vec()
        )
    }

    #[test]
    fn bitcoin_address_to_p2wsh_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: Payload::WitnessProgram(WitnessProgram::new(
                WitnessVersion::V0,
                b"65f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3".to_vec(),
            )),
        };

        let script = bitcoin_address.to_script();
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
            ba.payload.to_vec(),
            b"65f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3".to_vec()
        )
    }

    // #[test]
    fn bitcoin_address_to_p2tr_and_back() {
        let bitcoin_address = BitcoinAddress {
            network: BitcoinNetwork::Bitcoin,
            payload: Payload::WitnessProgram(WitnessProgram::new(
                WitnessVersion::V1,
                b"c1d58db5e33fb78f8aef613c54b5af72061faa6809d6dc849bb6c512f5fe56bcac".to_vec(),
            )),
        };

        let script = bitcoin_address.to_script();
        assert!(script.is_ok());
        let script = script.unwrap();
        assert_eq!(
            script.value(),
            b"20c1d58db5e33fb78f8aef613c54b5af72061faa6809d6dc849bb6c512f5fe56bcac"
        );

        let ba = BitcoinAddress::from_script(script, BitcoinNetwork::Bitcoin);
        assert!(ba.is_ok());
        let ba = ba.unwrap();
        assert_eq!(
            ba.payload.to_vec(),
            b"c1d58db5e33fb78f8aef613c54b5af72061faa6809d6dc849bb6c512f5fe56bcac".to_vec()
        )
    }

    #[test]
    fn bitcoin_address_from_contract() {
        const CONTRACT_ADDRESS: &str =
            "tb1plltrggq7p02uz8x7su2ajxzuhp05uvr5jv8tm49xumjkuceq84xqeynrkc";

        let script_pk: ScriptPubkey = BitcoinAddress::from_str(CONTRACT_ADDRESS).unwrap().to_script().unwrap();
        println!("{:?}", std::str::from_utf8(&script_pk.value()).unwrap());

        // let p = hex::encode(vec![255, 214, 52, 32, 30, 11, 213, 193, 28, 222, 135, 21, 217, 24, 92, 184, 95, 78, 48, 116, 147, 14, 189, 212, 166, 230, 229, 110, 99, 32, 61, 76]);
    }
}
