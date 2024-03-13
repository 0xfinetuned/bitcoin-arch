use std::fmt::Display;
use std::io::{Error, ErrorKind};
use opcodes::all::*;
use crate::types::ScriptTypes;


pub fn is_pubkey_hash(data: &[u8]) -> bool {
    return true
}

pub fn is_script_hash(data: &[u8]) -> bool {
    return true
}

pub fn get_script_type(script: &[u8]) -> Result<ScriptTypes, std::io::Error> {
    if is_p2pkh(script) {
        return Ok(ScriptTypes::P2PKH)
    }
    if is_p2sh(script) {
        return Ok(ScriptTypes::P2SH)
    }
    if is_p2wpkh(script) {
        return Ok(ScriptTypes::P2WPKH)
    }
    if is_p2wsh(script) {
        return Ok(ScriptTypes::P2WSH)
    }
    if is_op_return(script) {
        return Ok(ScriptTypes::OPReturn)
    }
    return Err(Error::new(ErrorKind::InvalidData, "invalid script"))
}

fn is_p2pkh(data: &[u8]) -> bool {
    let hex_str = std::str::from_utf8(data).expect("invalid p2pkh script pubkey");
    hex_str.len() == 50
    && &hex_str[..2] == format!("{:x?}", OP_DUP.to_u8())
    && &hex_str[2..4] == format!("{:x?}", OP_HASH160.to_u8())
    && &hex_str[4..6] == format!("{:x?}", OP_PUSHBYTES_20.to_u8())
    && &hex_str[46..48] == format!("{:x?}", OP_EQUALVERIFY.to_u8())
    && &hex_str[48..] == format!("{:x?}", OP_CHECKSIG.to_u8())
}

fn is_p2sh(data: &[u8]) -> bool {
    let hex_str = std::str::from_utf8(data).expect("invalid p2sh script pubkey");
    hex_str.len() == 46
    && &hex_str[..2] == format!("{:x?}", OP_HASH160.to_u8())
    && &hex_str[2..4] == format!("{:x?}", OP_PUSHBYTES_20.to_u8())
    && &hex_str[44..] == format!("{:x?}", OP_EQUAL.to_u8())
}

fn is_p2wpkh(data: &[u8]) -> bool {
    let hex_str = std::str::from_utf8(data).expect("invalid p2wpkh script pubkey");
    hex_str.len() == 44
    && &hex_str[..2] == "00"
    && &hex_str[2..4] == format!("{:x?}", OP_PUSHBYTES_20.to_u8())
}

fn is_p2wsh(data: &[u8]) -> bool {
    let hex_str = std::str::from_utf8(data).expect("invalid p2wsh script pubkey");
    hex_str.len() == 68 && &hex_str[..2] == "00"
    && &hex_str[2..4] == format!("{:x?}", OP_PUSHBYTES_32.to_u8())
}

fn is_op_return(data: &[u8]) -> bool {
    let hex_str = std::str::from_utf8(data).expect("invalid op_return script pubkey");
    &hex_str[..2] == format!("{:x?}", OP_RETURN.to_u8())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn is_p2pkh_works() {
        let test_cases = vec![b"76a91455ae51684c43435da751ac8d2173b2652eb6410588ac"];
        for test_case in test_cases {
            assert!(is_p2pkh(test_case))
        }
    }

    #[test]
    fn is_p2pkh_should_fail() {
        let test_cases = vec![b"a914748284390f9e263a4b766a75d0633c50426eb87587"];
        for test_case in test_cases {
            assert!(!is_p2pkh(test_case))
        }
    }

    #[test]
    fn is_p2sh_works() {
        let test_cases = vec![b"a914748284390f9e263a4b766a75d0633c50426eb87587"];
        for test_case in test_cases {
            assert!(is_p2sh(test_case))
        }
    }

    #[test]
    fn is_p2sh_should_fail() {
        let test_cases = vec![b"76a91455ae51684c43435da751ac8d2173b2652eb6410588ac"];
        for test_case in test_cases {
            assert!(!is_p2sh(test_case))
        }
    }
}
