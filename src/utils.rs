use opcodes::all::*;

pub fn bytes_to_hex_str(bytes: &[u8]) -> String {
    let mut s = String::new();
    bytes
        .iter()
        .for_each(|b| s.push_str(format!("{:x?}", b).as_str()));
    s
}

pub fn is_pubkey_hash(data: &[u8]) -> bool {
    return true
}

pub fn is_script_hash(data: &[u8]) -> bool {
    return true
}

pub fn is_p2sh(data: &[u8]) -> bool {
    return data.len() == 23 && data[0] == OP_HASH160.to_u8() && data[1] == OP_PUSHBYTES_20.to_u8() && data[22] == OP_EQUAL.to_u8()
}

#[cfg(test)]
mod test {
    use crate::utils::bytes_to_hex_str;

    #[test]
    fn to_hex_str_works() {
        let test_cases = vec![
            ((b"hello").to_vec(), "68656c6c6f".to_string()),
            ((b"Hello world!").to_vec(), "48656c6c6f20776f726c6421".to_string()),
            ((b"bitcoin").to_vec(), "626974636f696e".to_string()),
            (
                (b"where's waldo?").to_vec(),
                "776865726527732077616c646f3f".to_string(),
            ),
        ];

        for test_case in test_cases {
            let res = bytes_to_hex_str(&test_case.0);
            assert_eq!(res.clone(), test_case.1.clone());
            assert_eq!(res, hex::encode(&test_case.0))
        }
    }

    #[test]
    fn hex_crate_works() {
        let b = vec![53, 53, 97, 101, 53, 49, 54, 56, 52, 99, 52, 51, 52, 51, 53, 100, 97, 55, 53, 49, 97, 99, 56, 100, 50, 49, 55, 51, 98, 50, 54, 53, 50, 101, 98, 54, 52, 49, 48, 53];
        assert_eq!(hex::encode(b), "55ae51684c43435da751ac8d2173b2652eb64105")
    }
}
