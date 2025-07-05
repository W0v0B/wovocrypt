#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    InvalidLength,
    InvalidBufferSize,
}