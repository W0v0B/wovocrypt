use zeroize::Zeroize;
use super::BlockCipher;

#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
pub struct Aes128Key([u8; 16]);
impl AsRef<[u8]> for Aes128Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for Aes128Key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl From<[u8; 16]> for Aes128Key {
    fn from(array: [u8; 16]) -> Self {
        Self(array)
    }
}
impl From<Aes128Key> for [u8; 16] {
    fn from(output: Aes128Key) -> [u8; 16] {
        output.0
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Aes128 {
    expanded_key: [[u8; 4]; 44]
}

impl BlockCipher for Aes128 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 16;
    type Block = [u8; 16];
    type Key = Aes128Key;

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

