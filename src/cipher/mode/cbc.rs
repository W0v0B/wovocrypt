use core::marker::PhantomData;

use crate::cipher::BlockCipher;
use crate::padding::Padding;
use super::{SymcDecryptor, SymcEncryptor};

pub struct CbcEncryptor<C: BlockCipher, P: Padding> {
    cipher: C,
    iv: C::Block,
    buffer: C::Block,
    buffer_len: usize,
    _phantom: PhantomData<P>
}
impl<C: BlockCipher, P: Padding> Clone for CbcEncryptor<C, P>
where C: Clone, C::Block: Clone {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            iv: self.iv.clone(),
            buffer: self.buffer.clone(),
            buffer_len: self.buffer_len,
            _phantom: PhantomData
        }
    }
}

pub struct CbcDecryptor<C: BlockCipher, P: Padding>{
    cipher: C,
    iv: C::Block,
    buffer: C::Block,
    buffer_len: usize,
    _phantom: PhantomData<P>
}
impl<C: BlockCipher, P: Padding> Clone for CbcDecryptor<C, P>
where C: Clone, C::Block: Clone {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            iv: self.iv.clone(),
            buffer: self.buffer.clone(),
            buffer_len: self.buffer_len,
            _phantom: PhantomData
        }
    }
}

impl<C: BlockCipher, P: Padding> SymcEncryptor for CbcEncryptor<C, P> {
    type Key = C::Key;
    type IV = C::Block;

    fn new(key: &Self::Key, iv: &Self::IV) -> Self {
        Self {
            cipher: C::new(key),
            iv: iv.clone(),
            buffer: Default::default(),
            buffer_len: 0,
            _phantom: PhantomData
        }
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, crate::error::SymcError> {
        let block_size = C::BLOCK_SIZE;
        let mut written = 0;

        if output.len() < (self.buffer_len + input.len()) / block_size * block_size {
            return Err(crate::error::SymcError::BufferTooSmall);
        }

        let remaining = block_size - self.buffer_len;
        if remaining > input.len() {
            self.buffer.as_mut()[self.buffer_len..(self.buffer_len + input.len())].copy_from_slice(&input);
            self.buffer_len += input.len();
            return Ok(0);
        }

        self.buffer.as_mut()[self.buffer_len..].copy_from_slice(&input[..remaining]);
        self.buffer.as_mut().iter_mut()
            .zip(self.iv.as_ref().iter())
            .for_each(|(b, p)| *b ^= *p);
        self.cipher.encrypt_block(&mut self.buffer);
        written += block_size;
        output[..written].copy_from_slice(self.buffer.as_ref());
        self.buffer_len = 0;
        
        let mut chunks = input[remaining..].chunks_exact(block_size);
        for chunk in &mut chunks {
            self.buffer.as_mut().copy_from_slice(chunk);
            self.buffer.as_mut().iter_mut()
                .zip(output[(written - block_size)..written].iter())
                .for_each(|(b, p)| *b ^= *p);
            self.cipher.encrypt_block(&mut self.buffer);
            written += block_size;
            output[(written - block_size)..written].copy_from_slice(self.buffer.as_ref());
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            self.buffer.as_mut()[..remainder.len()].copy_from_slice(remainder);
            self.buffer_len = remainder.len();
        }
        self.iv.as_mut().copy_from_slice(&output[(written - block_size)..written]);
        
        Ok(written)
    }

    fn finalize(self, output: &mut [u8]) -> Result<usize, crate::error::SymcError> {
        unimplemented!()
    }
    
    fn reset(&mut self, iv: &Self::IV) {
        self.iv = iv.clone();
        self.buffer_len = 0;
    }
}

impl<C: BlockCipher, P: Padding> SymcDecryptor for CbcDecryptor<C, P> {
    type Key = C::Key;
    type IV = C::Block;

    fn new(key: &Self::Key, iv: &Self::IV) -> Self {
        Self {
            cipher: C::new(key),
            iv: iv.clone(),
            buffer: Default::default(),
            buffer_len: 0,
            _phantom: PhantomData
        }
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, crate::error::SymcError> {
        unimplemented!()
    }

    fn finalize(self, output: &mut [u8]) -> Result<usize, crate::error::SymcError> {
        unimplemented!()
    }
    
    fn reset(&mut self, iv: &Self::IV) {
        self.iv = iv.clone();
        self.buffer_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cipher::aes::prelude::{Aes128, Aes128Key}, padding::pkcs7::Pkcs7};

    /// Test vector from NIST SP 800-38A, Appendix F.2.1
    const KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    const IV: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    const P1: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    ];
    const C1: [u8; 16] = [
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    ];
    const P2: [u8; 16] = [
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    ];
    const C2: [u8; 16] = [
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    ];

    #[test]
    fn cbc_single_block_update() {
        let key = Aes128Key::from(KEY);
        let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&key, &IV.into());
        let mut output = [0u8; 16];
        
        let written = encryptor.update(&P1, &mut output).unwrap();
        
        assert_eq!(written, 16);
        assert_eq!(&output[..written], &C1);
    }

    #[test]
    fn cbc_multi_block_update() {
        let key = Aes128Key::from(KEY);
        let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&key, &IV.into());
        
        let plaintext = [P1, P2].concat();
        let expected_ciphertext = [C1, C2].concat();
        let mut output = [0u8; 32];

        let written = encryptor.update(&plaintext, &mut output).unwrap();

        assert_eq!(written, 32);
        assert_eq!(&output[..written], &expected_ciphertext);
    }

    #[test]
    fn cbc_partial_updates() {
        let key = Aes128Key::from(KEY);
        let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&key, &IV.into());
        let mut output = [0u8; 16];

        // First partial update, should write nothing and buffer
        let written1 = encryptor.update(&P1[..10], &mut output).unwrap();
        assert_eq!(written1, 0);

        // Second update, completes the first block
        let written2 = encryptor.update(&P1[10..], &mut output).unwrap();
        assert_eq!(written2, 16);
        assert_eq!(&output[..16], &C1);
    }
    
    #[test]
    fn cbc_nist_vector_step_by_step() {
        let key = Aes128Key::from(KEY);
        let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&key, &IV.into());
        let mut output = [0u8; 32];

        // Encrypt the first block
        let written1 = encryptor.update(&P1, &mut output[..16]).unwrap();
        assert_eq!(written1, 16);
        assert_eq!(&output[..16], &C1, "Ciphertext of block 1 is incorrect");

        // Encrypt the second block
        let written2 = encryptor.update(&P2, &mut output[16..]).unwrap();
        assert_eq!(written2, 16);
        assert_eq!(&output[16..32], &C2, "Ciphertext of block 2 is incorrect");
    }
}