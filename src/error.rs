#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SymcError {
    InvalidLength,
    InvalidPadding,
    BufferTooSmall
}