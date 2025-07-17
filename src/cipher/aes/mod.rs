use zeroize::Zeroize;

mod consts;
mod internal;
mod aes128;
mod aes192;
mod aes256;

pub trait BlockCipher: Zeroize {
    const BLOCK_SIZE: usize;
    const KEY_SIZE: usize;
    type Block: AsMut<[u8]> + AsRef<[u8]> + Default + Clone;
    type Key: AsRef<[u8]> + Default + Clone + Zeroize;

    fn new(key: &Self::Key) -> Self;

    fn encrypt_block(&self, block: &mut Self::Block);

    fn decrypt_block(&self, block: &mut Self::Block);
}

pub mod prelude {
    pub use super::BlockCipher;

    #[cfg(feature = "aes128")]
    pub use super::aes128::*;

    #[cfg(feature = "aes192")]
    pub use super::aes192::*;

    #[cfg(feature = "aes256")]
    pub use super::aes256::*;
}