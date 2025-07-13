use zeroize::Zeroize;
use super::BlockCipher;
use super::consts::{S_BOX, INV_S_BOX, RCON};

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

impl Aes128 {
    fn key_expansion(key: &self::Aes128Key) -> [[u8; 4]; 44] {
        // create 44 word array
        let mut w = [[0u8; 4]; 44];
        let nk = 4; // For AES-128, Nk = 4 words
        let mut rcon_index = 0;

        // copy key into the first Nk words
        w[0].copy_from_slice(&key.as_ref()[0..4]);
        w[1].copy_from_slice(&key.as_ref()[4..8]);
        w[2].copy_from_slice(&key.as_ref()[8..12]);
        w[3].copy_from_slice(&key.as_ref()[12..16]);

        // generate the rest of the words
        for i in nk..w.len() {
            let mut temp = u32::from_be_bytes(w[i - 1]);

            // apply transformations if i is a multiple of Nk.
            if i % nk == 0 {
                // rotate left word: [a, b, c, d] -> [b, c, d, a]
                temp = temp.rotate_left(8);

                // replace the bytes of temp with S_BOX
                let mut bytes = temp.to_be_bytes();
                for byte in &mut bytes {
                    *byte = S_BOX[*byte as usize];
                }
                temp = u32::from_be_bytes(bytes);

                // XOR with the RCON
                temp ^= RCON[rcon_index];
                rcon_index += 1;
            }

            // final XOR to get the new word
            let prev_word = u32::from_be_bytes(w[i - nk]);
            w[i] = (prev_word ^ temp).to_be_bytes();
        }

        w
    }
}

impl BlockCipher for Aes128 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 16;
    type Block = [u8; 16];
    type Key = Aes128Key;

    fn new(key: &Self::Key) -> Self {
        Self { expanded_key: Self::key_expansion(key) }
    }

    fn encrypt_block(&self, block: &mut Self::Block) {
        unimplemented!()
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        unimplemented!()
    }
}

