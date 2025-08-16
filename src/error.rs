#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SymcError {
    InvalidLength,
    InvalidInputLength,
    InvalidPadding,
    BufferTooSmall
}