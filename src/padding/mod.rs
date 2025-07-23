use crate::error::SymcError;

pub mod pkcs7;

pub trait Padding {
    fn pad(data: &[u8], output: &mut [u8], block_size: usize) -> Result<usize, SymcError>;
    
    fn unpad(data: &[u8], block_size: usize) -> Result<usize, SymcError>;
}