#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SymcError {
    InvalidLength,
    InvalidBufferSize,
}