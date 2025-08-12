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
        if output.len() < C::BLOCK_SIZE {
            return Err(crate::error::SymcError::BufferTooSmall);
        }

        let mut final_blocks: C::Block = Default::default();
        let padded_len = P::pad(&self.buffer.as_ref()[..self.buffer_len], final_blocks.as_mut(), C::BLOCK_SIZE)?;
        final_blocks.as_mut().iter_mut()
            .zip(self.iv.as_ref().iter())
            .for_each(|(b, p)| *b ^= p);
        self.cipher.encrypt_block(&mut final_blocks);
        output[..C::BLOCK_SIZE].copy_from_slice(final_blocks.as_ref());

        Ok(padded_len)
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
        let block_size = C::BLOCK_SIZE;
        let mut written = 0;

        // 计算 self.buffer_len 还剩多少空间
        let remaining = block_size - self.buffer_len;
        // 如果 input.len() 不超过 remaining 则直接拷贝进 self.buffer 退出
        if remaining >= input.len() {
            self.buffer.as_mut()[self.buffer_len..(self.buffer_len + input.len())].copy_from_slice(&input);
            self.buffer_len += input.len();
            return Ok(0);
        }

        // 计算剩余的 input 处理完 16 字节对齐后还剩多少，确保 tail_len 一定存在并且小于等于 16 字节
        let tail_len = ((input.len() - remaining - 1) & 0xF) + 1;
        // 除去 tail_len，本次需要处理的 input 长度，head_len 一定是 16 字节对齐的
        let head_len = input.len() - tail_len - remaining;

        // 总计 head_len 加上一个块 (之前遗留的数据 + input 补充的数据，一定是一个块的大小)
        if output.len() < head_len + block_size {
            return Err(crate::error::SymcError::BufferTooSmall);
        }

        // 处理第一个块
        self.buffer.as_mut()[self.buffer_len..].copy_from_slice(&input[..remaining]);
        // 保存 iv 值到 output
        output[..block_size].copy_from_slice(self.iv.as_mut());
        // 保存这次的加密块作为下次的 iv 值
        self.iv.as_mut().copy_from_slice(self.buffer.as_mut());
        self.cipher.decrypt_block(&mut self.buffer);
        // 原地异或得到明文
        output[..block_size].iter_mut()
            .zip(self.buffer.as_ref().iter())
            .for_each(|(b, p)| *b ^= *p);
        written += block_size;
        self.buffer_len = 0;

        // 每 16 字节循环处理 head 整块
        let mut process_len = 0;
        while process_len < head_len {
            // 拿取 input remaining 长度后的每 16 字节数据
            self.buffer.as_mut().copy_from_slice(&input[(remaining + process_len)..(remaining + process_len + block_size)]);
            // 保存 iv 值到 output
            output[written..(written + block_size)].copy_from_slice(self.iv.as_mut());
            // 保存这次的加密块作为下次的 iv 值
            self.iv.as_mut().copy_from_slice(self.buffer.as_mut());
            self.cipher.decrypt_block(&mut self.buffer);
            // 原地异或得到明文
            output[written..(written + block_size)].iter_mut()
                .zip(self.buffer.as_ref().iter())
                .for_each(|(b, p)| *b ^= *p);
            written += block_size;
            process_len += block_size;
        }

        // 拷贝剩下的 tail，tail_len 一定小于或等于 16 字节
        self.buffer.as_mut()[..tail_len].copy_from_slice(&input[(remaining + head_len)..]);
        self.buffer_len = tail_len;

        Ok(written)
    }

    fn finalize(mut self, output: &mut [u8]) -> Result<usize, crate::error::SymcError> {
        let block_size = C::BLOCK_SIZE;

        if self.buffer_len != block_size {
            return Err(crate::error::SymcError::InvalidPadding);
        }

        self.cipher.decrypt_block(&mut self.buffer);
        self.buffer.as_mut().iter_mut()
            .zip(self.iv.as_ref().iter())
            .for_each(|(b, p)| *b ^= p);

        let unpadded_len = P::unpad(self.buffer.as_ref(), block_size)?;
        if output.len() < unpadded_len {
            return Err(crate::error::SymcError::BufferTooSmall);
        }

        let final_plaintext = &self.buffer.as_ref()[..unpadded_len];
        output[..unpadded_len].copy_from_slice(final_plaintext);

        Ok(unpadded_len)
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

    mod encryptor_tests {
        use super::*;

        #[test]
        fn cbc_encrypt_update() {
            let key = Aes128Key::from(KEY);
            let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&key, &IV.into());
            let mut input = [0u8; (P1.len() + P2.len() / 2)];
            let mut output = [0u8; (P1.len() + P2.len())];

            input[..P1.len()].copy_from_slice(&P1);
            input[P1.len()..].copy_from_slice(&P2[0..(P2.len() / 2)]);
            
            let written1 = encryptor.update(&input, &mut output).unwrap();
            assert_eq!(written1, P1.len());
            assert_eq!(&output[..written1], &C1);
            assert_eq!(encryptor.buffer[0..(P2.len() / 2)], P2[0..(P2.len() / 2)]);
            assert_eq!(encryptor.buffer_len, (P2.len() / 2));

            let written2 = encryptor.update(&P2[(P2.len() / 2)..], &mut output[written1..]).unwrap();
            assert_eq!(written2, P2.len());
            assert_eq!(&output[written1..], &C2);
            assert_eq!(encryptor.buffer_len, 0);

            assert_eq!(written1 + written2, &C1.len() + &C2.len());
            assert_eq!(&output[..written1], &C1);
            assert_eq!(&output[written1..(written1 + written2)], &C2);
        }

        #[test]
        fn cbc_encrypt_finalize() {
            let expected_final_block: [u8; 16] = [
                0x67, 0x11, 0x4e, 0x5e, 0x43, 0xd8, 0x37, 0x8e,
                0x2a, 0xf3, 0x29, 0x6f, 0x65, 0x4e, 0x4c, 0xbf
            ];

            let key = Aes128Key::from(KEY);
            let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&key, &C1.into());
            
            encryptor.buffer.as_mut()[..10].copy_from_slice(&P2[..10]);
            encryptor.buffer_len = 10;

            let mut output = [0u8; 16];
            let written = encryptor.finalize(&mut output).unwrap();

            assert_eq!(written, expected_final_block.len());
            assert_eq!(&output, &expected_final_block);
        }

        #[test]
        fn cbc_encrypt_finalize_empty_buffer() {
            let key = Aes128Key::from(KEY);
            let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&key, &IV.into());
            
            let mut output = [0u8; 32];
            let written1 = encryptor.update(&P1, &mut output).unwrap();
            assert_eq!(written1, C1.len());
            assert_eq!(&output[..C1.len()], &C1);

            let written2 = encryptor.finalize(&mut output[C1.len()..]).unwrap();
            assert_eq!(written2, Aes128::BLOCK_SIZE);

            let mut expected_pad_block = [16u8; 16];
            expected_pad_block.iter_mut()
                .zip(C1.iter())
                .for_each(|(b, p)| *b ^= p);
            let cipher = Aes128::new(&key);
            cipher.encrypt_block(&mut expected_pad_block);
            
            assert_eq!(&output[C1.len()..], &expected_pad_block);
        }
    }

    mod decryptor_tests {
        use super::*;

        #[test]
        fn cbc_decrypt_update() {
            let key = Aes128Key::from(KEY);
            let mut decryptor = CbcDecryptor::<Aes128, Pkcs7>::new(&key, &IV.into());
            let mut output = [0u8; (C1.len() + C2.len())];

            let written1 = decryptor.update(&C1, &mut output).unwrap();
            assert_eq!(written1, 0);
            assert_eq!(decryptor.buffer, C1);
            assert_eq!(decryptor.buffer_len, C1.len());

            let written2 = decryptor.update(&C2[..(C2.len() / 2)], &mut output).unwrap();
            assert_eq!(written2, P1.len());
            assert_eq!(decryptor.buffer[..(C2.len() / 2)], C2[..(C2.len() / 2)]);
            assert_eq!(decryptor.buffer_len, (C2.len() / 2));
            assert_eq!(output[..P1.len()], P1);

            let written3 = decryptor.update(&C2[(C2.len() / 2)..], &mut output).unwrap();
            assert_eq!(written3, 0);
            assert_eq!(decryptor.buffer_len, C2.len());
            assert_eq!(decryptor.buffer, C2);
        }

        #[test]
        fn cbc_decrypt_finalize() {
            let c1_iv_p2_10_byte_encrypt: [u8; 16] = [
                0x67, 0x11, 0x4e, 0x5e, 0x43, 0xd8, 0x37, 0x8e,
                0x2a, 0xf3, 0x29, 0x6f, 0x65, 0x4e, 0x4c, 0xbf
            ];
            
            let key = Aes128Key::from(KEY);
            let mut decryptor = CbcDecryptor::<Aes128, Pkcs7>::new(&key, &C1.into());
            let mut output = [0u8; 10];

            let written1 = decryptor.update(&c1_iv_p2_10_byte_encrypt, &mut output).unwrap();
            assert_eq!(written1, 0);
            assert_eq!(decryptor.buffer_len, c1_iv_p2_10_byte_encrypt.len());

            let written2 = decryptor.finalize(&mut output).unwrap();
            assert_eq!(written2, output.len());
            assert_eq!(output, P2[0..10]);
        }

        #[test]
        fn cbc_decrypt_finalize_pad_16_block() {
            let pad_16_encrypt_block: [u8; 16] = [
                0xc8, 0x4a, 0xf0, 0xb6, 0x13, 0x43, 0x5d, 0x5d,
                0x91, 0x82, 0x80, 0x1a, 0x9b, 0xd9, 0x32, 0x0b
            ];

            let key = Aes128Key::from(KEY);
            let mut decryptor = CbcDecryptor::<Aes128, Pkcs7>::new(&key, &IV.into());
            let mut output = [0u8; 16];

            let written1 = decryptor.update(&pad_16_encrypt_block, &mut output).unwrap();
            assert_eq!(written1, 0);
            assert_eq!(decryptor.buffer_len, pad_16_encrypt_block.len());

            let written2 = decryptor.finalize(&mut output).unwrap();
            assert_eq!(written2, 0);
        }
    }
}