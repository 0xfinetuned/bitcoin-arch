use crate::types::ScriptTypes;
use opcodes::all::*;
use std::io::{Error, ErrorKind};

pub fn get_script_type(script: &[u8]) -> Result<ScriptTypes, std::io::Error> {
    if is_p2pkh(script) {
        return Ok(ScriptTypes::P2PKH);
    }
    if is_p2sh(script) {
        return Ok(ScriptTypes::P2SH);
    }
    if is_p2wpkh(script) {
        return Ok(ScriptTypes::P2WPKH);
    }
    if is_p2wsh(script) {
        return Ok(ScriptTypes::P2WSH);
    }
    if is_p2tr(script) {
        return Ok(ScriptTypes::P2TR);
    }
    if is_op_return(script) {
        return Ok(ScriptTypes::OPReturn);
    }
    Err(Error::new(ErrorKind::InvalidData, "invalid script"))
}

fn is_p2pkh(data: &[u8]) -> bool {
    let hex_data = hex::decode(data).expect("invalid p2pkh script pubkey");
    hex_data.len() == 25
        && hex_data[0] == OP_DUP.to_u8()
        && hex_data[1] == OP_HASH160.to_u8()
        && hex_data[2] == OP_PUSHBYTES_20.to_u8()
        && hex_data[23] == OP_EQUALVERIFY.to_u8()
        && hex_data[24] == OP_CHECKSIG.to_u8()
}

fn is_p2sh(data: &[u8]) -> bool {
    let hex_data = hex::decode(data).expect("invalid p2sh script pubkey");
    hex_data.len() == 23
        && hex_data[0] == OP_HASH160.to_u8()
        && hex_data[1] == OP_PUSHBYTES_20.to_u8()
        && hex_data[22] == OP_EQUAL.to_u8()
}

fn is_p2wpkh(data: &[u8]) -> bool {
    let hex_data = hex::decode(data).expect("invalid p2wpkh script pubkey");
    hex_data.len() == 22
        && hex_data[0] == 0
        && hex_data[1] == OP_PUSHBYTES_20.to_u8()
}

fn is_p2wsh(data: &[u8]) -> bool {
    let hex_data = hex::decode(data).expect("invalid p2wsh script pubkey");
    hex_data.len() == 34
        && hex_data[0] == 0
        && hex_data[1] == OP_PUSHBYTES_32.to_u8()
}

fn is_p2tr(data: &[u8]) -> bool {
    let hex_data = hex::decode(data).expect("invalid p2tr script");
    return hex_data.len() == 34 && hex_data[0] == OP_PUSHNUM_1.to_u8() && hex_data[1] == OP_PUSHBYTES_32.to_u8()
}

fn is_op_return(data: &[u8]) -> bool {
    let hex_str = std::str::from_utf8(data).expect("invalid op_return script pubkey");
    hex_str[..2] == format!("{:x?}", OP_RETURN.to_u8())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_script_type_works() {
        // p2pkh
        assert!(is_p2pkh(
            b"76a91455ae51684c43435da751ac8d2173b2652eb6410588ac"
        ));
        assert!(!is_p2pkh(b"a914748284390f9e263a4b766a75d0633c50426eb87587"));

        // p2sh
        assert!(is_p2sh(b"a914748284390f9e263a4b766a75d0633c50426eb87587"));
        assert!(!is_p2sh(
            b"76a91455ae51684c43435da751ac8d2173b2652eb6410588ac"
        ));

        // p2wpkh
        assert!(is_p2wpkh(b"0014853ec3166860371ee67b7754ff85e13d7a0d6698"));
        assert!(!is_p2wpkh(b"0114853ec3166860371ee67b7754ff85e13d7a0d6698"));

        // p2wsh
        assert!(is_p2wsh(
            b"002065f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3"
        ));
        assert!(!is_p2wsh(
            b"001465f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3"
        ));

        // p2tr
        assert!(is_p2tr(b"5120ffd634201e0bd5c11cde8715d9185cb85f4e3074930ebdd4a6e6e56e63203d4c"));
        assert!(!is_p2tr(b"001465f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3"));


        // op_return
        assert!(is_op_return(b"6a0b68656c6c6f20776f726c64"));
        assert!(!is_op_return(
            b"76a91455ae51684c43435da751ac8d2173b2652eb6410588ac"
        ));
    }
}
