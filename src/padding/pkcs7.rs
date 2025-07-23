use super::{Padding, SymcError};

pub struct Pkcs7;

impl Padding for Pkcs7 {
    fn pad(data: &[u8], output: &mut [u8], block_size: usize) -> Result<usize, SymcError> {
        if block_size == 0 || block_size > 255 {
            return Err(SymcError::InvalidLength);
        }

        let padding_len = block_size - (data.len() % block_size);
        let total_len = data.len() + padding_len;

        if output.len() < total_len {
            return Err(SymcError::BufferTooSmall);
        }

        let output = &mut output[..total_len];
        if !data.is_empty() {
            output[..data.len()].copy_from_slice(data);
        }
        output[data.len()..].fill(padding_len as u8);

        Ok(total_len)
    }

    fn unpad(data: &[u8], block_size: usize) -> Result<usize, SymcError> {
        if block_size == 0 || block_size > 255 {
            return Err(SymcError::InvalidLength);
        }

        if data.is_empty() || data.len() % block_size != 0 {
            return Err(SymcError::InvalidPadding);
        }

        let padding_len = data[data.len() - 1] as usize;
        if padding_len == 0 || padding_len > block_size || padding_len > data.len() {
            return Err(SymcError::InvalidPadding);
        }

        let start_idx = data.len() - padding_len;
        for i in start_idx..data.len() {
            if data[i] != padding_len as u8 {
                return Err(SymcError::InvalidPadding);
            }
        }

        Ok(data.len() - padding_len)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn test_pkcs7_pad_basic() {
        let mut output = [0u8; 16];
        let data = b"hello";
        let result = Pkcs7::pad(data, &mut output, 8);
        
        assert_eq!(result, Ok(8));
        assert_eq!(&output[..8], &[b'h', b'e', b'l', b'l', b'o', 3, 3, 3]);
    }
    
    #[test]
    fn test_pkcs7_pad_full_block() {
        let mut output = [0u8; 16];
        let data = b"12345678";
        let result = Pkcs7::pad(data, &mut output, 8);
        
        assert_eq!(result, Ok(16));
        assert_eq!(&output[..16], b"12345678\x08\x08\x08\x08\x08\x08\x08\x08");
    }
    
    #[test]
    fn test_pkcs7_unpad_basic() {
        let data = &[b'h', b'e', b'l', b'l', b'o', 3, 3, 3];
        let result = Pkcs7::unpad(data, 8);
        
        assert_eq!(result, Ok(5));
    }
    
    #[test]
    fn test_pkcs7_unpad_full_block() {
        let data = b"12345678\x08\x08\x08\x08\x08\x08\x08\x08";
        let result = Pkcs7::unpad(data, 8);
        
        assert_eq!(result, Ok(8));
    }
    
    #[test]
    fn test_pkcs7_unpad_invalid_padding() {
        let data = &[b'h', b'e', b'l', b'l', b'o', 3, 3, 2];
        let result = Pkcs7::unpad(data, 8);
        
        assert_eq!(result, Err(SymcError::InvalidPadding));
    }
    
    #[test]
    fn test_pkcs7_unpad_invalid_length() {
        let data = &[b'h', b'e', b'l', b'l', b'o'];
        let result = Pkcs7::unpad(data, 8);
        
        assert_eq!(result, Err(SymcError::InvalidPadding));
    }
    
    #[test]
    fn test_insufficient_capacity() {
        let mut output = [0u8; 4];
        let data = b"hello";
        let result = Pkcs7::pad(data, &mut output, 8);
        
        assert_eq!(result, Err(SymcError::BufferTooSmall));
    }
    
    #[test]
    fn test_roundtrip() {
        let original = b"The quick brown fox";
        let mut padded = [0u8; 32];
        let block_size = 16;
        
        let padded_len = Pkcs7::pad(original, &mut padded, block_size).unwrap();
        
        let unpadded_len = Pkcs7::unpad(&padded[..padded_len], block_size).unwrap();
        
        assert_eq!(&padded[..unpadded_len], original);
    }
}

