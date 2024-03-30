use crate::script::Script;
use crate::types::{self, SEGWIT_V0_PUBKEY_HASH_LEN, SEGWIT_V0_SCRIPT_HASH_LEN};
use crate::types::{BitcoinNetwork, Payload, ScriptType, WitnessProgram, WitnessVersion};
use crate::utils::get_script_type_with_payload;
use anyhow::{anyhow, Result};
use std::io::{Error, ErrorKind};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct BitcoinAddress {
    pub network: BitcoinNetwork,
    pub payload: Payload,
}

impl PartialEq for BitcoinAddress {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network && self.payload == other.payload
    }
}

impl Eq for BitcoinAddress {}

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
    pub fn to_script(&self) -> Result<Script> {
        match &self.payload {
            Payload::PubkeyHash(data) => Ok(Script::new_p2pkh(data)),
            Payload::ScriptHash(data) => Ok(Script::new_p2sh(data)),
            Payload::WitnessProgram(program) => match program.version {
                WitnessVersion::V0 => match program.data.len() {
                    SEGWIT_V0_PUBKEY_HASH_LEN => Ok(Script::new_p2wpkh(&program.data)),
                    SEGWIT_V0_SCRIPT_HASH_LEN => Ok(Script::new_p2wsh(&program.data)),
                    _ => Err(anyhow!("invalid witness program data")),
                },
                WitnessVersion::V1 => Ok(Script::new_p2tr(&program.data)),
            },
        }
    }

    pub fn from_script(script: Script, network: BitcoinNetwork) -> Result<Self> {
        let (script_type, script_data) = get_script_type_with_payload(script.as_bytes())?;
        let payload = match script_type {
            ScriptType::P2PKH => Some(Payload::PubkeyHash(script_data)),
            ScriptType::P2SH => Some(Payload::ScriptHash(script_data)),
            ScriptType::P2WPKH | ScriptType::P2WSH => Some(Payload::WitnessProgram(
                WitnessProgram::new(WitnessVersion::V0, script_data),
            )),
            ScriptType::P2TR => Some(Payload::WitnessProgram(WitnessProgram::new(
                WitnessVersion::V1,
                script_data,
            ))),
            ScriptType::OPReturn => None,
        };

        // no support for OP_RETURN scripts yet
        if payload.is_none() {
            return Err(anyhow!("script type is invalid"));
        }

        Ok(BitcoinAddress {
            network,
            payload: payload.unwrap(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const P2PKH_TESTNET_ADDRESS: &str = "mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt";
    const P2PKH_BITCOIN_ADDRESS: &str = "12higDjoCCNXSA95xZMWUdPvXNmkAduhWv";

    const P2SH_TESTNET_ADDRESS: &str = "2Mw3bN3ESQ8rNBRvT8vMwuRGtv1Sagnmx3K";
    const P2SH_BITCOIN_ADDRESS: &str = "342ftSRCvFHfCeFFBuz4xwbeqnDw6BGUey";

    const P2WPKH_TESTNET_ADDRESS: &str = "tb1q0wd9zhh68uac6mxeyxrnjspaamfr4mu9apqluy";
    const P2WPKH_BITCOIN_ADDRESS: &str = "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c";

    const P2WSH_TESTNET_ADDRESS: &str =
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
    const P2WSH_BITCOIN_ADDRESS: &str =
        "bc1qeklep85ntjz4605drds6aww9u0qr46qzrv5xswd35uhjuj8ahfcqgf6hak";

    const P2TR_TESTNET_ADDRESS: &str =
        "tb1plltrggq7p02uz8x7su2ajxzuhp05uvr5jv8tm49xumjkuceq84xqeynrkc";
    const P2TR_BITCOIN_ADDRESS: &str =
        "bc1pxwww0ct9ue7e8tdnlmug5m2tamfn7q06sahstg39ys4c9f3340qqxrdu9k";

    fn assert_bitcoin_address_to_script(address: &str, network: BitcoinNetwork) {
        let expected_address = BitcoinAddress::from_str(address).unwrap();

        let actual_script = expected_address.to_script();
        assert!(actual_script.is_ok());

        let actual_script = actual_script.unwrap();

        let btc_network = match network {
            BitcoinNetwork::Bitcoin => bitcoin::network::Network::Bitcoin,
            BitcoinNetwork::Testnet => bitcoin::network::Network::Testnet,
            BitcoinNetwork::Signet => bitcoin::network::Network::Signet,
            BitcoinNetwork::Regtest => bitcoin::network::Network::Regtest,
        };

        let expected_script = bitcoin::address::Address::from_str(address)
            .unwrap()
            .require_network(btc_network)
            .unwrap()
            .script_pubkey();

        assert_eq!(actual_script.as_bytes(), expected_script.as_bytes());

        let actual_address = BitcoinAddress::from_script(actual_script, network).unwrap();
        assert_eq!(actual_address, expected_address);
    }

    #[test]
    fn bitcoin_address_to_p2pkh_and_back() {
        assert_bitcoin_address_to_script(P2PKH_TESTNET_ADDRESS, BitcoinNetwork::Testnet);
        assert_bitcoin_address_to_script(P2PKH_BITCOIN_ADDRESS, BitcoinNetwork::Bitcoin);
    }

    #[test]
    fn bitcoin_address_to_p2sh_and_back() {
        assert_bitcoin_address_to_script(P2SH_TESTNET_ADDRESS, BitcoinNetwork::Testnet);
        assert_bitcoin_address_to_script(P2SH_BITCOIN_ADDRESS, BitcoinNetwork::Bitcoin);
    }

    #[test]
    fn bitcoin_address_to_p2wpkh_and_back() {
        assert_bitcoin_address_to_script(P2WPKH_TESTNET_ADDRESS, BitcoinNetwork::Testnet);
        assert_bitcoin_address_to_script(P2WPKH_BITCOIN_ADDRESS, BitcoinNetwork::Bitcoin);
    }

    #[test]
    fn bitcoin_address_to_p2wsh_and_back() {
        assert_bitcoin_address_to_script(P2WSH_TESTNET_ADDRESS, BitcoinNetwork::Testnet);
        assert_bitcoin_address_to_script(P2WSH_BITCOIN_ADDRESS, BitcoinNetwork::Bitcoin);
    }

    #[test]
    fn bitcoin_address_to_p2tr_and_back() {
        assert_bitcoin_address_to_script(P2TR_TESTNET_ADDRESS, BitcoinNetwork::Testnet);
        assert_bitcoin_address_to_script(P2TR_BITCOIN_ADDRESS, BitcoinNetwork::Bitcoin);
    }
}
