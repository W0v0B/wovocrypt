use zeroize::Zeroize;

pub mod aes;

pub mod mode;

pub trait BlockCipher: Zeroize + Clone {
    const BLOCK_SIZE: usize;
    const KEY_SIZE: usize;
    type Block: AsRef<[u8]> + AsMut<[u8]> + Clone + Default + Zeroize;
    type Key: AsRef<[u8]> + Default + Clone + Zeroize;

    fn new(key: &Self::Key) -> Self;

    fn encrypt_block(&self, block: &mut Self::Block);

    fn decrypt_block(&self, block: &mut Self::Block);
}