use super::{Padding, SymcError};

pub struct NoPadding;

impl Padding for NoPadding {
    fn pad(data: &[u8], output: &mut [u8], block_size: usize) -> Result<usize, SymcError> {
        if data.len() % block_size != 0 {
            return Err(SymcError::InvalidInputLength);
        }
        if output.len() < data.len() {
            return Err(SymcError::BufferTooSmall);
        }

        output[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    fn unpad(data: &[u8], block_size: usize) -> Result<usize, SymcError> {
       if data.len() % block_size != 0 {
            return Err(SymcError::InvalidInputLength);
        }
        Ok(data.len())
    }
}