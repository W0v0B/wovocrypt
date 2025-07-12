use zeroize::Zeroize;
use super::BlockCipher;

#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
pub struct Aes192Key([u8; 24]);
impl AsRef<[u8]> for Aes192Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for Aes192Key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl From<[u8; 24]> for Aes192Key {
    fn from(array: [u8; 24]) -> Self {
        Self(array)
    }
}
impl From<Aes192Key> for [u8; 24] {
    fn from(output: Aes192Key) -> [u8; 24] {
        output.0
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Aes192 {
    expanded_key: [[u8; 4]; 52]
}

impl BlockCipher for Aes192 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 24;
    type Block = [u8; 16];
    type Key = Aes192Key;

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

