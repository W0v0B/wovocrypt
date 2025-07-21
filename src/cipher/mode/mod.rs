use crate::error::SymcError;
use zeroize::Zeroize;

mod cbc;

pub trait SymcEncryptor: Sized + Clone {
    type Key: AsRef<[u8]> + Default + Clone + Zeroize;
    type IV: AsRef<[u8]> + AsMut<[u8]> + Clone + Default + Zeroize;

    fn new(key: &Self::Key, iv: &Self::IV) -> Self;

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, SymcError>;

    fn finalize(self, output: &mut [u8]) -> Result<usize, SymcError>;

    fn encrypt(key: &Self::Key, iv: &Self::IV, input: &[u8], output: &mut [u8]) -> Result<usize, SymcError> {
        let mut encryptor = Self::new(key, iv);
        let mut written = encryptor.update(input, output)?;
        written += encryptor.finalize(&mut output[written..])?;
        Ok(written)
    }

    fn reset(&mut self, iv: &Self::IV);

    fn finalize_and_reset(&mut self, iv: &Self::IV, output: &mut [u8]) -> Result<usize, SymcError> {
        let clone = (*self).clone();
        let written = clone.finalize(output)?;
        self.reset(iv);
        Ok(written)
    }
}

pub trait SymcDecryptor: Sized + Clone {
    type Key: AsRef<[u8]> + Default + Clone + Zeroize;
    type IV: AsRef<[u8]> + AsMut<[u8]> + Clone + Default + Zeroize;

    fn new(key: &Self::Key, iv: &Self::IV) -> Self;

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, SymcError>;

    fn finalize(self, output: &mut [u8]) -> Result<usize, SymcError>;

    fn decrypt(key: &Self::Key, iv: &Self::IV, input: &[u8], output: &mut [u8]) -> Result<usize, SymcError> {
        let mut decryptor = Self::new(key, iv);
        let mut written = decryptor.update(input, output)?;
        written += decryptor.finalize(&mut output[written..])?;
        Ok(written)
    }

    fn reset(&mut self, iv: &Self::IV);

    fn finalize_and_reset(&mut self, iv: &Self::IV, output: &mut [u8]) -> Result<usize, SymcError> {
        let clone = (*self).clone();
        let written = clone.finalize(output)?;
        self.reset(iv);
        Ok(written)
    }
}

pub mod prelude {
    use crate::cipher::aes::prelude::{Aes128, Aes192, Aes256};

    pub type AesCbc128Encryptor = super::cbc::CbcEncryptor<Aes128>;
    pub type AesCbc128Decryptor = super::cbc::CbcDecryptor<Aes128>;

    pub type AesCbc192Encryptor = super::cbc::CbcEncryptor<Aes192>;
    pub type AesCbc192Decryptor = super::cbc::CbcDecryptor<Aes192>;

    pub type AesCbc256Encryptor = super::cbc::CbcEncryptor<Aes256>;
    pub type AesCbc256Decryptor = super::cbc::CbcDecryptor<Aes256>;
}