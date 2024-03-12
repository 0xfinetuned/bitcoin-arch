pub fn bytes_to_hex_str(bytes: &[u8]) -> String {
    let mut s = String::new();
    bytes
        .iter()
        .for_each(|b| s.push_str(format!("{:x?}", b).as_str()));
    s
}

#[cfg(test)]
mod test {
    use crate::utils::bytes_to_hex_str;

    #[test]
    fn to_hex_str_works() {
        let test_cases = vec![
            ((b"hello").to_vec(), "68656c6c6f".to_string()),
            ((b"bitcoin").to_vec(), "626974636f696e".to_string()),
            (
                (b"where's waldo?").to_vec(),
                "776865726527732077616c646f3f".to_string(),
            ),
        ];

        for test_case in test_cases {
            let res = bytes_to_hex_str(&test_case.0);
            assert_eq!(res, test_case.1);
        }
    }
}
