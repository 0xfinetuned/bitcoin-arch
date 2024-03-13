#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BitcoinNetwork {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}
