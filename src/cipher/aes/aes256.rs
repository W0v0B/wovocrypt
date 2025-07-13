use zeroize::Zeroize;
use super::BlockCipher;
use super::consts::{S_BOX, INV_S_BOX, RCON};

#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
pub struct Aes256Key([u8; 32]);
impl AsRef<[u8]> for Aes256Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for Aes256Key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl From<[u8; 32]> for Aes256Key {
    fn from(array: [u8; 32]) -> Self {
        Self(array)
    }
}
impl From<Aes256Key> for [u8; 32] {
    fn from(output: Aes256Key) -> [u8; 32] {
        output.0
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Aes256 {
    expanded_key: [[u8; 4]; 60]
}

impl BlockCipher for Aes256 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 32;
    type Block = [u8; 16];
    type Key = Aes256Key;

    fn new(key: &Self::Key) -> Self {
        unimplemented!()
    }

    fn encrypt_block(&self, block: &mut Self::Block) {
        unimplemented!()
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        unimplemented!()
    }
}

