use opcodes::Opcode;

use super::script::Script;

pub struct ScriptBuilder(Script);

impl ScriptBuilder {
    pub fn new() -> Self {
        ScriptBuilder(Script(Vec::new()))
    }

    pub fn push_opcode(&mut self, opcode: Opcode) -> &mut Self {
        self.0.push_value(opcode.to_u8());
        self
    }

    // push_int only supports 0, -1 and 1 to 16 for now
    pub fn push_int(&mut self, data: i64) -> &mut Self {
        if data == 0 {
            self.push_opcode(opcodes::OP_0);
            return self;
        }

        if data == -1 || (1..=16).contains(&data) {
            let opcode = Opcode::from((data - 1 + opcodes::OP_TRUE.to_u8() as i64) as u8);
            self.push_opcode(opcode);
            return self;
        }

        panic!("invalid integer to push");
    }

    pub fn push_slice_only(&mut self, data: &[u8]) -> &mut Self {
        self.0.push_slice(data);
        self
    }

    pub fn push_slice_with_size(&mut self, data: &[u8]) -> &mut Self {
        // TODO(chinonso): Handle large streams of data
        self.push_opcode(Opcode::from(data.len() as u8));
        self.0.push_slice(data);
        self
    }

    pub fn push_x_only_key(&mut self, x_only_key: &[u8]) -> &mut Self {
        todo!()
    }

    pub fn into_script(self) -> Script {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use opcodes::all::*;

    #[test]
    fn push_opcode_works() {
        let mut builder = ScriptBuilder::new();

        builder.push_opcode(OP_PUSHBYTES_32);
        assert_eq!(builder.0 .0[0], OP_PUSHBYTES_32.to_u8());

        builder.push_opcode(OP_PUSHNUM_1);
        assert_eq!(builder.0 .0[1], OP_PUSHNUM_1.to_u8());

        builder.push_opcode(OP_RETURN);
        assert_eq!(builder.0 .0[2], OP_RETURN.to_u8());
    }

    #[test]
    fn push_int_works() {
        let mut builder = ScriptBuilder::new();

        builder.push_int(-1);
        assert_eq!(builder.0 .0[0], OP_PUSHNUM_NEG1.to_u8());

        builder.push_int(2);
        assert_eq!(builder.0 .0[1], OP_PUSHNUM_2.to_u8());

        builder.push_int(0);
        assert_eq!(builder.0 .0[2], opcodes::OP_0.to_u8());

        builder.push_int(1);
        assert_eq!(builder.0 .0[3], OP_PUSHNUM_1.to_u8());
    }

    #[test]
    #[should_panic]
    fn push_int_panics() {
        let mut builder = ScriptBuilder::new();
        builder.push_int(17);
    }

    #[test]
    fn push_slice_works() {
        let mut builder = ScriptBuilder::new();

        builder.push_slice_with_size(&[55, 56, 57]);
        assert_eq!(builder.0 .0, vec![3, 55, 56, 57]);

        builder.push_slice_with_size(&[
            255, 214, 52, 32, 30, 11, 213, 193, 28, 222, 135, 21, 217, 24, 92, 184, 95, 78, 48,
            116, 147, 14, 189, 212, 166, 230, 229, 110, 99, 32, 61, 76,
        ]);
        assert_eq!(
            builder.0 .0,
            vec![
                3, 55, 56, 57, 32, 255, 214, 52, 32, 30, 11, 213, 193, 28, 222, 135, 21, 217, 24,
                92, 184, 95, 78, 48, 116, 147, 14, 189, 212, 166, 230, 229, 110, 99, 32, 61, 76
            ]
        );
    }
}
