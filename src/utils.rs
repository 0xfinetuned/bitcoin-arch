use crate::types::ScriptType;
use opcodes::all::*;

pub fn get_script_type_with_payload(script: &[u8]) -> Result<(ScriptType, Vec<u8>), &'static str> {
    // check if script is p2pkh
    if script.len() == 25
        && script[0] == OP_DUP.to_u8()
        && script[1] == OP_HASH160.to_u8()
        && script[2] == OP_PUSHBYTES_20.to_u8()
        && script[23] == OP_EQUALVERIFY.to_u8()
        && script[24] == OP_CHECKSIG.to_u8()
    {
        return Ok((ScriptType::P2PKH, script[3..23].to_vec()));
    }

    // check if script is p2sh
    if script.len() == 23
        && script[0] == OP_HASH160.to_u8()
        && script[1] == OP_PUSHBYTES_20.to_u8()
        && script[22] == OP_EQUAL.to_u8()
    {
        return Ok((ScriptType::P2SH, script[2..22].to_vec()));
    }

    // check if script is p2wpkh
    if script.len() == 22 && script[0] == 0 && script[1] == OP_PUSHBYTES_20.to_u8() {
        return Ok((ScriptType::P2WPKH, script[2..].to_vec()));
    }

    // check if script is p2wsh
    if script.len() == 34 && script[0] == 0 && script[1] == OP_PUSHBYTES_32.to_u8() {
        return Ok((ScriptType::P2WSH, script[2..].to_vec()));
    }

    // check if script is p2tr
    if script.len() == 34
        && script[0] == OP_PUSHNUM_1.to_u8()
        && script[1] == OP_PUSHBYTES_32.to_u8()
    {
        return Ok((ScriptType::P2TR, script[2..].to_vec()));
    }

    // check if script is op_return
    if script[0] == OP_RETURN.to_u8() {
        return Ok((ScriptType::OPReturn, vec![]));
    }

    Err("invalid script")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_script_type_with_payload_works() {
        let p2pkh_script = vec![
            118, 169, 20, 52, 74, 15, 72, 202, 21, 14, 194, 185, 3, 129, 118, 96, 185, 182, 139,
            19, 166, 112, 38, 136, 172,
        ];
        let p2sh_script = vec![
            169, 20, 41, 173, 90, 200, 129, 34, 139, 98, 191, 122, 229, 9, 170, 61, 153, 113, 243,
            183, 134, 181, 135,
        ];
        let p2wpkh_script = vec![
            0, 20, 123, 154, 81, 94, 250, 63, 59, 141, 108, 217, 33, 135, 57, 64, 61, 238, 210, 58,
            239, 133,
        ];
        let p2wsh_script = vec![
            0, 32, 24, 99, 20, 60, 20, 197, 22, 104, 4, 189, 25, 32, 51, 86, 218, 19, 108, 152, 86,
            120, 205, 77, 39, 161, 184, 198, 50, 150, 4, 144, 50, 98,
        ];
        let p2tr_script = vec![
            81, 32, 255, 214, 52, 32, 30, 11, 213, 193, 28, 222, 135, 21, 217, 24, 92, 184, 95, 78,
            48, 116, 147, 14, 189, 212, 166, 230, 229, 110, 99, 32, 61, 76,
        ];

        let p2pkh_data = p2pkh_script[3..23].to_vec();
        let p2sh_data = p2sh_script[2..22].to_vec();
        let p2wpkh_data = p2wpkh_script[2..].to_vec();
        let p2wsh_data = p2wsh_script[2..].to_vec();
        let p2tr_data = p2tr_script[2..].to_vec();

        let test_cases = vec![
            (&p2pkh_script, (ScriptType::P2PKH, p2pkh_data)),
            (&p2sh_script, (ScriptType::P2SH, p2sh_data)),
            (&p2wpkh_script, (ScriptType::P2WPKH, p2wpkh_data)),
            (&p2wsh_script, (ScriptType::P2WSH, p2wsh_data)),
            (&p2tr_script, (ScriptType::P2TR, p2tr_data)),
        ];

        for (script, actual_result) in test_cases {
            let expected_result = get_script_type_with_payload(script).unwrap();
            assert_eq!(actual_result, expected_result);
        }
    }
}
