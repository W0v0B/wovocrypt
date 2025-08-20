use zeroize::Zeroize;

use crate::cipher::BlockCipher;
use super::{SymcDecryptor, SymcEncryptor};

#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
pub struct CtrNonce(pub [u8; 12]);
impl AsRef<[u8]> for CtrNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for CtrNonce {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl From<[u8; 12]> for CtrNonce {
    fn from(array: [u8; 12]) -> Self {
        Self(array)
    }
}
impl From<CtrNonce> for [u8; 12] {
    fn from(output: CtrNonce) -> Self {
        output.0
    }
}

pub struct CtrEncryptor<C: BlockCipher> {
    cipher: C,
    nonce_counter: C::Block,
    buffer: C::Block,
    buffer_len: usize,
}
impl<C: BlockCipher> Clone for CtrEncryptor<C>
where C: Clone, C::Block: Clone {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            nonce_counter: self.nonce_counter.clone(),
            buffer: self.buffer.clone(),
            buffer_len: self.buffer_len,
        }
    }
}

pub struct CtrDecryptor<C: BlockCipher>{
    cipher: C,
    nonce_counter: C::Block,
    buffer: C::Block,
    buffer_len: usize,
}
impl<C: BlockCipher> Clone for CtrDecryptor<C>
where C: Clone, C::Block: Clone {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            nonce_counter: self.nonce_counter.clone(),
            buffer: self.buffer.clone(),
            buffer_len: self.buffer_len,
        }
    }
}

impl<C: BlockCipher> SymcEncryptor for CtrEncryptor<C> {
    type Key = C::Key;
    type IV = CtrNonce;
    
    fn new(key: &Self::Key, iv: &Self::IV) -> Self {
        let mut nonce_counter_block: C::Block = Default::default();
        nonce_counter_block.as_mut()[..12].copy_from_slice(iv.as_ref());

        Self {
            cipher: C::new(key),
            nonce_counter: nonce_counter_block,
            buffer: Default::default(),
            buffer_len: 0
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
        let mut keystream_block = self.nonce_counter.clone();
        self.cipher.encrypt_block(&mut keystream_block);
        output[..block_size].iter_mut()
            .zip(self.buffer.as_ref().iter())
            .zip(keystream_block.as_ref().iter())
            .for_each(|((o, b), k)| *o = *b ^ *k);

        let counter_bytes = &mut self.nonce_counter.as_mut()[12..];
        let counter = u32::from_be_bytes(counter_bytes.try_into().unwrap());

        counter_bytes.copy_from_slice(&counter.wrapping_add(1).to_be_bytes());
        written += block_size;
        self.buffer_len = 0;

        let mut chunks = input[remaining..].chunks_exact(block_size);
        for chunk in &mut chunks {
            let keystream_block = {
                let mut temp = self.nonce_counter.clone();
                self.cipher.encrypt_block(&mut temp);
                temp
            };

            output[written..(written + block_size)].iter_mut()
                .zip(chunk.iter())
                .zip(keystream_block.as_ref().iter())
                .for_each(|((o, i), k)| *o = *i ^ *k);

            let counter_bytes = &mut self.nonce_counter.as_mut()[12..];
            let counter = u32::from_be_bytes(counter_bytes.try_into().unwrap());
            counter_bytes.copy_from_slice(&counter.wrapping_add(1).to_be_bytes());

            written += block_size;
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            self.buffer.as_mut()[..remainder.len()].copy_from_slice(remainder);
            self.buffer_len = remainder.len();
        }

        Ok(written)
    }

    fn finalize(self, output: &mut [u8]) -> Result<usize, crate::error::SymcError> {
        if output.len() < self.buffer_len {
            return Err(crate::error::SymcError::BufferTooSmall);
        }

        if self.buffer_len == 0 {
            return Ok(0);
        }

        let mut keystream_block = self.nonce_counter;
        self.cipher.encrypt_block(&mut keystream_block);

        output.iter_mut()
            .zip(&self.buffer.as_ref()[..self.buffer_len])
            .zip(&keystream_block.as_ref()[..self.buffer_len])
            .for_each(|((o, p), k)| *o = *p ^ *k);

        Ok(self.buffer_len)
    }

    fn reset(&mut self, iv: &Self::IV) {
        self.nonce_counter.as_mut()[..12].copy_from_slice(iv.as_ref());
        self.nonce_counter.as_mut()[12..].fill(0);
        self.buffer_len = 0;
    }
}

impl<C: BlockCipher> SymcDecryptor for CtrDecryptor<C> {
    type Key = C::Key;
    type IV = CtrNonce;
    
    fn new(key: &Self::Key, iv: &Self::IV) -> Self {
        let mut nonce_counter_block: C::Block = Default::default();
        nonce_counter_block.as_mut()[..12].copy_from_slice(iv.as_ref());

        Self {
            cipher: C::new(key),
            nonce_counter: nonce_counter_block,
            buffer: Default::default(),
            buffer_len: 0
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
        let mut keystream_block = self.nonce_counter.clone();
        self.cipher.encrypt_block(&mut keystream_block);
        output[..block_size].iter_mut()
            .zip(self.buffer.as_ref().iter())
            .zip(keystream_block.as_ref().iter())
            .for_each(|((o, b), k)| *o = *b ^ *k);

        let counter_bytes = &mut self.nonce_counter.as_mut()[12..];
        let counter = u32::from_be_bytes(counter_bytes.try_into().unwrap());

        counter_bytes.copy_from_slice(&counter.wrapping_add(1).to_be_bytes());
        written += block_size;
        self.buffer_len = 0;

        let mut chunks = input[remaining..].chunks_exact(block_size);
        for chunk in &mut chunks {
            let keystream_block = {
                let mut temp = self.nonce_counter.clone();
                self.cipher.encrypt_block(&mut temp);
                temp
            };

            output[written..(written + block_size)].iter_mut()
                .zip(chunk.iter())
                .zip(keystream_block.as_ref().iter())
                .for_each(|((o, i), k)| *o = *i ^ *k);

            let counter_bytes = &mut self.nonce_counter.as_mut()[12..];
            let counter = u32::from_be_bytes(counter_bytes.try_into().unwrap());
            counter_bytes.copy_from_slice(&counter.wrapping_add(1).to_be_bytes());

            written += block_size;
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            self.buffer.as_mut()[..remainder.len()].copy_from_slice(remainder);
            self.buffer_len = remainder.len();
        }

        Ok(written)
    }

    fn finalize(self, output: &mut [u8]) -> Result<usize, crate::error::SymcError> {
        if output.len() < self.buffer_len {
            return Err(crate::error::SymcError::BufferTooSmall);
        }

        if self.buffer_len == 0 {
            return Ok(0);
        }

        let mut keystream_block = self.nonce_counter;
        self.cipher.encrypt_block(&mut keystream_block);

        output.iter_mut()
            .zip(&self.buffer.as_ref()[..self.buffer_len])
            .zip(&keystream_block.as_ref()[..self.buffer_len])
            .for_each(|((o, p), k)| *o = *p ^ *k);

        Ok(self.buffer_len)
    }

    fn reset(&mut self, iv: &Self::IV) {
        self.nonce_counter.as_mut()[..12].copy_from_slice(iv.as_ref());
        self.nonce_counter.as_mut()[12..].fill(0);
        self.buffer_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::{Aes128, Aes128Key};

    /// Test vector from NIST SP 800-38A, Appendix F.5.1
    const KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    const IV: [u8; 12] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb,
    ];
    const P1: [u8; 32] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    ];
    const C1: [u8; 32] = [
        0x22, 0xe5, 0x2f, 0xb1, 0x77, 0xd8, 0x65, 0xb2,
        0xf7, 0xc6, 0xb5, 0x12, 0x69, 0x2d, 0x11, 0x4d,
        0xed, 0x6c, 0x1c, 0x72, 0x25, 0xda, 0xf6, 0xa2,
        0xaa, 0xd9, 0xd3, 0xda, 0x2d, 0xba, 0x21, 0x68
    ];
    const P2: [u8; 16] = [
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    ];
    const C2: [u8; 16] = [
        0xe7, 0x09, 0x1b, 0x04, 0x47, 0x9b, 0x56, 0xb8,
        0x80, 0x4c, 0xa4, 0xaf, 0x5f, 0x11, 0x88, 0x36
    ];

    mod encryptor_tests {
        use super::*;

        #[test]
        fn ctr_encrypt_update() {
            let key = Aes128Key::from(KEY);
            let mut encryptor = CtrEncryptor::<Aes128>::new(&key, &IV.into());
            let mut output = [0u8; C1.len()];
            
            let written1 = encryptor.update(&P1[..(P1.len() / 4 * 3)], &mut output).unwrap();
            assert_eq!(written1, (P1.len() / 2));
            assert_eq!(&output[..written1], &C1[..(C1.len() / 2)]);
            assert_eq!(encryptor.buffer_len, (P1.len() / 4));
            assert_eq!(encryptor.buffer[0..(P1.len() / 4)], P1[(P1.len() / 2)..(P1.len() / 4 * 3)]);
            
            let written2 = encryptor.update(&P1[(P1.len() / 4 * 3)..], &mut output[written1..]).unwrap();
            assert_eq!(written2, (P1.len() / 2));
            assert_eq!(&output[written1..], &C1[(C1.len() / 2)..]);
            assert_eq!(encryptor.buffer_len, 0);

            assert_eq!(written1 + written2, C1.len());
            assert_eq!(&output, &C1);
        }

        #[test]
        fn ctr_encrypt_finalize() {
            let key = Aes128Key::from(KEY);
            let mut encryptor = CtrEncryptor::<Aes128>::new(&key, &IV.into());
            let mut output = [0u8; C2.len()];

            let mut written1 = encryptor.update(&P2[..(P2.len() - 1)], &mut output).unwrap();
            assert_eq!(written1, 0);
            assert_eq!(encryptor.buffer_len, (P2.len() - 1));
            assert_eq!(encryptor.buffer[0..(P2.len() - 1)], P2[..(P2.len() - 1)]);

            written1 += encryptor.finalize(&mut output).unwrap();
            assert_eq!(written1, (C2.len() - 1));
            assert_eq!(&output[..(C2.len() - 1)], &C2[..(C2.len() - 1)]);
        }
    }

    mod decryptor_tests {
        use super::*;

        #[test]
        fn ctr_decrypt_update() {
            let key = Aes128Key::from(KEY);
            let mut decryptor = CtrDecryptor::<Aes128>::new(&key, &IV.into());
            let mut output = [0u8; P1.len()];
            
            let written1 = decryptor.update(&C1[..(C1.len() / 4 * 3)], &mut output).unwrap();
            assert_eq!(written1, (C1.len() / 2));
            assert_eq!(&output[..written1], &P1[..(P1.len() / 2)]);
            assert_eq!(decryptor.buffer_len, (P1.len() / 4));
            assert_eq!(decryptor.buffer[0..(P1.len() / 4)], C1[(C1.len() / 2)..(C1.len() / 4 * 3)]);
            
            let written2 = decryptor.update(&C1[(C1.len() / 4 * 3)..], &mut output[written1..]).unwrap();
            assert_eq!(written2, (C1.len() / 2));
            assert_eq!(&output[written1..], &P1[(P1.len() / 2)..]);
            assert_eq!(decryptor.buffer_len, 0);

            assert_eq!(written1 + written2, P1.len());
            assert_eq!(&output, &P1);
        }

        #[test]
        fn ctr_decrypt_finalize() {
            let key = Aes128Key::from(KEY);
            let mut decryptor = CtrDecryptor::<Aes128>::new(&key, &IV.into());
            let mut output = [0u8; C2.len()];

            let mut written1 = decryptor.update(&C2[..(C2.len() - 1)], &mut output).unwrap();
            assert_eq!(written1, 0);
            assert_eq!(decryptor.buffer_len, (C2.len() - 1));
            assert_eq!(decryptor.buffer[0..(C2.len() - 1)], C2[..(C2.len() - 1)]);

            written1 += decryptor.finalize(&mut output).unwrap();
            assert_eq!(written1, (P2.len() - 1));
            assert_eq!(&output[..(P2.len() - 1)], &P2[..(P2.len() - 1)]);
        }
    }
}