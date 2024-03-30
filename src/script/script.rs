use super::builder::ScriptBuilder;
use opcodes::all::*;

pub struct Script(pub(in crate::script) Vec<u8>);

impl Script {
    pub(in crate::script) fn push_value(&mut self, data: u8) {
        self.0.push(data);
    }

    pub(in crate::script) fn push_slice(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn new_p2pkh(data: &[u8]) -> Self {
        let mut builder = ScriptBuilder::new();
        builder
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_opcode(OP_PUSHBYTES_20)
            .push_slice_only(data)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG);
        builder.into_script()
    }

    pub fn new_p2sh(data: &[u8]) -> Self {
        let mut builder = ScriptBuilder::new();
        builder
            .push_opcode(OP_HASH160)
            .push_opcode(OP_PUSHBYTES_20)
            .push_slice_only(data)
            .push_opcode(OP_EQUAL);
        builder.into_script()
    }

    pub fn new_p2wpkh(data: &[u8]) -> Self {
        let mut builder = ScriptBuilder::new();
        builder
            .push_int(0)
            .push_opcode(OP_PUSHBYTES_20)
            .push_slice_only(data);
        builder.into_script()
    }

    pub fn new_p2wsh(data: &[u8]) -> Self {
        let mut builder = ScriptBuilder::new();
        builder
            .push_int(0)
            .push_opcode(OP_PUSHBYTES_32)
            .push_slice_only(data);
        builder.into_script()
    }

    pub fn new_p2tr(data: &[u8]) -> Self {
        let mut builder = ScriptBuilder::new();
        builder
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_PUSHBYTES_32)
            .push_slice_only(data);
        builder.into_script()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn push_value_works() {
        let mut script = Script(vec![]);
        script.push_value(1);
        assert_eq!(script.0[0], 1u8);
        script.push_value(2);
        assert_eq!(script.0[1], 2u8);
    }

    #[test]
    fn push_slice_works() {
        let mut script = Script(vec![]);
        script.push_slice(&[255, 214, 52, 32, 30, 11, 213, 193, 28, 222]);
        script.push_slice(&[135, 21, 217, 24, 92, 184, 95, 78, 48, 116, 147]);
        script.push_slice(&[14, 189, 212, 166, 230, 229, 110, 99, 32, 61, 76]);
        assert_eq!(
            script.0,
            [
                255, 214, 52, 32, 30, 11, 213, 193, 28, 222, 135, 21, 217, 24, 92, 184, 95, 78, 48,
                116, 147, 14, 189, 212, 166, 230, 229, 110, 99, 32, 61, 76
            ]
        );
    }

    #[test]
    fn as_bytes_works() {
        let mut script = Script(vec![]);
        script.push_slice(&[255, 214, 52, 32, 30, 11, 213, 193, 28, 222]);
        assert_eq!(
            script.as_bytes(),
            [255, 214, 52, 32, 30, 11, 213, 193, 28, 222]
        );
    }

    #[test]
    fn new_p2pkh_works() {
        let script = Script::new_p2pkh(&[
            52, 74, 15, 72, 202, 21, 14, 194, 185, 3, 129, 118, 96, 185, 182, 139, 19, 166, 112, 38,
        ]);
        assert_eq!(
            script.as_bytes(),
            [
                118, 169, 20, 52, 74, 15, 72, 202, 21, 14, 194, 185, 3, 129, 118, 96, 185, 182,
                139, 19, 166, 112, 38, 136, 172
            ]
        );
    }

    #[test]
    fn new_p2sh_works() {
        let script = Script::new_p2sh(&[
            41, 173, 90, 200, 129, 34, 139, 98, 191, 122, 229, 9, 170, 61, 153, 113, 243, 183, 134,
            181,
        ]);
        assert_eq!(
            script.as_bytes(),
            [
                169, 20, 41, 173, 90, 200, 129, 34, 139, 98, 191, 122, 229, 9, 170, 61, 153, 113,
                243, 183, 134, 181, 135
            ]
        );
    }

    #[test]
    fn new_p2wpkh_works() {
        let script = Script::new_p2wpkh(&[
            123, 154, 81, 94, 250, 63, 59, 141, 108, 217, 33, 135, 57, 64, 61, 238, 210, 58, 239,
            133,
        ]);
        assert_eq!(
            script.as_bytes(),
            [
                0, 20, 123, 154, 81, 94, 250, 63, 59, 141, 108, 217, 33, 135, 57, 64, 61, 238, 210,
                58, 239, 133
            ]
        );
    }

    #[test]
    fn new_p2wsh_works() {
        let script = Script::new_p2wsh(&[
            24, 99, 20, 60, 20, 197, 22, 104, 4, 189, 25, 32, 51, 86, 218, 19, 108, 152, 86, 120,
            205, 77, 39, 161, 184, 198, 50, 150, 4, 144, 50, 98,
        ]);
        assert_eq!(
            script.as_bytes(),
            [
                0, 32, 24, 99, 20, 60, 20, 197, 22, 104, 4, 189, 25, 32, 51, 86, 218, 19, 108, 152,
                86, 120, 205, 77, 39, 161, 184, 198, 50, 150, 4, 144, 50, 98
            ]
        );
    }

    #[test]
    fn new_p2tr_works() {
        let script = Script::new_p2tr(&[
            255, 214, 52, 32, 30, 11, 213, 193, 28, 222, 135, 21, 217, 24, 92, 184, 95, 78, 48,
            116, 147, 14, 189, 212, 166, 230, 229, 110, 99, 32, 61, 76,
        ]);
        assert_eq!(
            script.as_bytes(),
            [
                81, 32, 255, 214, 52, 32, 30, 11, 213, 193, 28, 222, 135, 21, 217, 24, 92, 184, 95,
                78, 48, 116, 147, 14, 189, 212, 166, 230, 229, 110, 99, 32, 61, 76
            ]
        );
    }
}
