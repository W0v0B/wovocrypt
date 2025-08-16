use crate::error::SymcError;

mod pkcs7;
pub use pkcs7::Pkcs7;

mod nopadding;
pub use nopadding::NoPadding;

pub trait Padding {
    fn pad(data: &[u8], output: &mut [u8], block_size: usize) -> Result<usize, SymcError>;
    
    fn unpad(data: &[u8], block_size: usize) -> Result<usize, SymcError>;
}