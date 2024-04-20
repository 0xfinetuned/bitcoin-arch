use crate::script::{error::ScriptError, ScriptBuf};
use core::convert::TryInto;

/// A "parsed opcode" which allows iterating over a [`Script`] in a more sensible way.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Instruction<'a> {
    /// Push a bunch of data.
    PushBytes(&'a [u8]),
    /// Some non-push opcode.
    Op(opcodes::Opcode),
}

impl<'a> Instruction<'a> {
    /// Returns the opcode if the instruction is not a data push.
    pub fn opcode(&self) -> Option<opcodes::Opcode> {
        match self {
            Instruction::Op(op) => Some(*op),
            Instruction::PushBytes(_) => None,
        }
    }

    /// Returns the pushed bytes if the instruction is a data push.
    pub fn push_bytes(&self) -> Option<&[u8]> {
        match self {
            Instruction::Op(_) => None,
            Instruction::PushBytes(bytes) => Some(bytes),
        }
    }
}

/// Iterator over a script returning parsed opcodes.
#[derive(Debug, Clone)]
pub struct Instructions<'a> {
    pub(crate) data: core::slice::Iter<'a, u8>,
    pub(crate) enforce_minimal: bool,
}

impl<'a> Instructions<'a> {
    /// Views the remaining script as a slice.
    pub fn as_script(&self) -> ScriptBuf {
        ScriptBuf::from(self.data.as_slice())
    }

    /// Sets the iterator to end so that it won't iterate any longer.
    pub(super) fn kill(&mut self) {
        let len = self.data.len();
        self.data.nth(len.max(1) - 1);
    }

    /// Takes a `len` bytes long slice from iterator and returns it, advancing the iterator.
    ///
    /// If the iterator is not long enough [`Error::EarlyEndOfScript`] is returned and the iterator
    /// is killed to avoid returning an infinite stream of errors.
    pub(super) fn take_slice_or_kill(&mut self, len: u32) -> Result<&'a [u8], ScriptError> {
        let len = len as usize;
        if self.data.len() >= len {
            let slice = &self.data.as_slice()[..len];
            if len > 0 {
                self.data.nth(len - 1);
            }

            Ok(slice
                .try_into()
                .expect("len was created from u32, so can't happen"))
        } else {
            self.kill();
            Err(ScriptError::EarlyEndOfScript)
        }
    }

    pub(super) fn next_push_data_len(
        &mut self,
        len: PushDataLenLen,
        min_push_len: usize,
    ) -> Option<Result<Instruction<'a>, ScriptError>> {
        let n = match read_uint_iter(&mut self.data, len as usize) {
            Ok(n) => n,
            // Overflow actually means early end of script (script is definitely shorter
            // than `usize::max_value()`)
            Err(ScriptError::EarlyEndOfScript) | Err(ScriptError::NumericOverflow) => {
                self.kill();
                return Some(Err(ScriptError::EarlyEndOfScript));
            }
            Err(_) => panic!("This error should not be possible"),
        };
        if self.enforce_minimal && n < min_push_len {
            self.kill();
            return Some(Err(ScriptError::NonMinimalPush));
        }
        let result = n
            .try_into()
            .map_err(|_| ScriptError::NumericOverflow)
            .and_then(|n| self.take_slice_or_kill(n))
            .map(Instruction::PushBytes);
        Some(result)
    }
}

impl<'a> From<&'a [u8]> for Instructions<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self {
            data: value.iter(),
            enforce_minimal: false,
        }
    }
}

// We internally use implementation based on iterator so that it automatically advances as needed
fn read_uint_iter(data: &mut core::slice::Iter<'_, u8>, size: usize) -> Result<usize, ScriptError> {
    if data.len() < size {
        Err(ScriptError::EarlyEndOfScript)
    } else if size > usize::from(u16::max_value() / 8) {
        // Casting to u32 would overflow
        Err(ScriptError::NumericOverflow)
    } else {
        let mut ret = 0;
        for (i, item) in data.take(size).enumerate() {
            ret = usize::from(*item)
                // Casting is safe because we checked above to not repeat the same check in a loop
                .checked_shl((i * 8) as u32)
                .ok_or(ScriptError::NumericOverflow)?
                .checked_add(ret)
                .ok_or(ScriptError::NumericOverflow)?;
        }
        Ok(ret)
    }
}

/// Allowed length of push data length.
///
/// This makes it easier to prove correctness of `next_push_data_len`.
pub(super) enum PushDataLenLen {
    One = 1,
    Two = 2,
    Four = 4,
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Result<Instruction<'a>, ScriptError>;

    fn next(&mut self) -> Option<Result<Instruction<'a>, ScriptError>> {
        let &byte = self.data.next()?;

        // classify parameter does not really matter here since we are only using
        // it for pushes and nums
        match opcodes::Opcode::from(byte).classify(opcodes::ClassifyContext::Legacy) {
            opcodes::Class::PushBytes(n) => {
                // make sure safety argument holds across refactorings
                let n: u32 = n;

                let op_byte = self.data.as_slice().first();
                match (self.enforce_minimal, op_byte, n) {
                    (true, Some(&op_byte), 1)
                        if op_byte == 0x81 || (op_byte > 0 && op_byte <= 16) =>
                    {
                        self.kill();
                        Some(Err(ScriptError::NonMinimalPush))
                    }
                    (_, None, 0) => {
                        // the iterator is already empty, may as well use this information to avoid
                        // whole take_slice_or_kill function
                        Some(Ok(Instruction::PushBytes(&[])))
                    }
                    _ => Some(self.take_slice_or_kill(n).map(Instruction::PushBytes)),
                }
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA1) => {
                self.next_push_data_len(PushDataLenLen::One, 76)
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA2) => {
                self.next_push_data_len(PushDataLenLen::Two, 0x100)
            }
            opcodes::Class::Ordinary(opcodes::Ordinary::OP_PUSHDATA4) => {
                self.next_push_data_len(PushDataLenLen::Four, 0x10000)
            }
            // Everything else we can push right through
            _ => Some(Ok(Instruction::Op(opcodes::Opcode::from(byte)))),
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.data.len() == 0 {
            (0, Some(0))
        } else {
            // There will not be more instructions than bytes
            (1, Some(self.data.len()))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn instruction_iter_works() {
        let test_cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                vec![
                    118, 169, 20, 26, 4, 122, 112, 147, 13, 37, 228, 38, 43, 80, 164, 8, 25, 151,
                    104, 201, 39, 5, 32, 136, 172,
                ],
                vec![
                    26, 4, 122, 112, 147, 13, 37, 228, 38, 43, 80, 164, 8, 25, 151, 104, 201, 39,
                    5, 32,
                ],
            ),
            (
                vec![
                    81, 32, 194, 6, 54, 189, 122, 249, 214, 176, 212, 81, 25, 74, 61, 133, 139,
                    144, 131, 104, 155, 56, 155, 214, 134, 105, 98, 55, 22, 172, 9, 212, 243, 118,
                ],
                vec![
                    194, 6, 54, 189, 122, 249, 214, 176, 212, 81, 25, 74, 61, 133, 139, 144, 131,
                    104, 155, 56, 155, 214, 134, 105, 98, 55, 22, 172, 9, 212, 243, 118,
                ],
            ),
            (
                vec![
                    169, 20, 20, 47, 137, 124, 19, 143, 239, 40, 162, 132, 109, 44, 59, 134, 222,
                    130, 110, 120, 14, 118, 135,
                ],
                vec![
                    20, 47, 137, 124, 19, 143, 239, 40, 162, 132, 109, 44, 59, 134, 222, 130, 110,
                    120, 14, 118,
                ],
            ),
            (
                vec![
                    169, 20, 141, 4, 220, 195, 232, 102, 18, 198, 104, 160, 169, 115, 17, 53, 134,
                    242, 102, 71, 125, 69, 135,
                ],
                vec![
                    141, 4, 220, 195, 232, 102, 18, 198, 104, 160, 169, 115, 17, 53, 134, 242, 102,
                    71, 125, 69,
                ],
            ),
        ];

        for (script_pubkey, expected_payload) in test_cases {
            let instructions = Instructions::from(script_pubkey.as_slice());
            let mut actual_payload = Vec::new();

            for result in instructions {
                match result {
                    Ok(Instruction::PushBytes(push)) => {
                        actual_payload.extend_from_slice(push);
                    }
                    Ok(Instruction::Op(_)) => {}
                    Err(_) => {}
                }
            }

            assert_eq!(actual_payload, expected_payload);
        }
    }
}
