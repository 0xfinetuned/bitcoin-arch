use core::fmt;

/// Ways that a script might fail.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ScriptError {
    /// Something did a non-minimal push; for more information see
    /// <https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#push-operators>
    NonMinimalPush,
    /// Some opcode expected a parameter but it was missing or truncated.
    EarlyEndOfScript,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes.
    NumericOverflow,
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ScriptError::NonMinimalPush => f.write_str("non-minimal datapush"),
            ScriptError::EarlyEndOfScript => f.write_str("unexpected end of script"),
            ScriptError::NumericOverflow => f.write_str("numeric overflow (number on stack larger than 4 bytes)"),
        }
    }
}
