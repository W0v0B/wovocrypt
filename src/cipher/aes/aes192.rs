use zeroize::Zeroize;
use super::super::BlockCipher;
use super::consts::{S_BOX, RCON};
use super::internal::{add_round_key, sub_bytes, shift_rows, mix_columns,
    inv_sub_bytes, inv_shift_rows, inv_mix_columns};

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

impl Aes192 {
    fn key_expansion(key: &self::Aes192Key) -> [[u8; 4]; 52] {
        // create 52 word array
        let mut w = [[0u8; 4]; 52];
        let nk = 6; // For AES-192, Nk = 6 words
        let mut rcon_index = 0;

        // copy key into the first Nk words
        w[0].copy_from_slice(&key.as_ref()[0..4]);
        w[1].copy_from_slice(&key.as_ref()[4..8]);
        w[2].copy_from_slice(&key.as_ref()[8..12]);
        w[3].copy_from_slice(&key.as_ref()[12..16]);
        w[4].copy_from_slice(&key.as_ref()[16..20]);
        w[5].copy_from_slice(&key.as_ref()[20..24]);

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

    #[inline]
    fn get_round_key(&self, round: usize) -> [[u8; 4]; 4] {
        let base = round * 4;
        [
            self.expanded_key[base],
            self.expanded_key[base + 1],
            self.expanded_key[base + 2],
            self.expanded_key[base + 3]
        ]
    }
}

impl BlockCipher for Aes192 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 24;
    type Block = [u8; 16];
    type Key = Aes192Key;

    fn new(key: &Self::Key) -> Self {
        Self { expanded_key: Self::key_expansion(key) }
    }

    fn encrypt_block(&self, block: &mut Self::Block) {
        let mut state = *block;

        // --- First Round ---
        // key injection
        add_round_key(&mut state, &self.get_round_key(0));

        // --- 11 Main Rounds ---
        for round in 1..=11 {
            // replace the bytes with S_BOX
            sub_bytes(&mut state);
            // row shift
            shift_rows(&mut state);
            // column confusion
            mix_columns(&mut state);
            // key injection
            add_round_key(&mut state, &self.get_round_key(round));
        }

        // --- Last Round (omits column confusion) ---
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.get_round_key(12));

        *block = state;
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        let mut state = *block;

        // --- First Round (from ciphertext) ---
        // decrypt the last round of encrypt block
        add_round_key(&mut state, &self.get_round_key(12));

        // --- 11 Main Rounds (in reverse order) ---
        for round in (1..=11).rev() {
            // inverse row shift
            inv_shift_rows(&mut state);
            // replace the bytes with INV_S_BOX
            inv_sub_bytes(&mut state);
            // decrypt the current round of encrypt block
            add_round_key(&mut state, &self.get_round_key(round));
            // inverse MixColumns matrix (inverse column confusion)
            inv_mix_columns(&mut state);
        }

        // --- Last Round (to get plaintext) ---
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        // decrypt the first round of encrypt block
        add_round_key(&mut state, &self.get_round_key(0));

        *block = state;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test the key expansion against the official FIPS-197 Appendix A.2 vector.
    #[test]
    fn fips_197_key_expansion_a2() {
        // The test key from Appendix A.2
        let key_bytes: [u8; 24] = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];

        // The expected expanded key words from FIPS-197, Appendix A.2
        let expected_w: [[u8; 4]; 52] = [
            [0x8e, 0x73, 0xb0, 0xf7], [0xda, 0x0e, 0x64, 0x52], [0xc8, 0x10, 0xf3, 0x2b],
            [0x80, 0x90, 0x79, 0xe5], [0x62, 0xf8, 0xea, 0xd2], [0x52, 0x2c, 0x6b, 0x7b],
            [0xfe, 0x0c, 0x91, 0xf7], [0x24, 0x02, 0xf5, 0xa5], [0xec, 0x12, 0x06, 0x8e],
            [0x6c, 0x82, 0x7f, 0x6b], [0x0e, 0x7a, 0x95, 0xb9], [0x5c, 0x56, 0xfe, 0xc2],
            [0x4d, 0xb7, 0xb4, 0xbd], [0x69, 0xb5, 0x41, 0x18], [0x85, 0xa7, 0x47, 0x96],
            [0xe9, 0x25, 0x38, 0xfd], [0xe7, 0x5f, 0xad, 0x44], [0xbb, 0x09, 0x53, 0x86],
            [0x48, 0x5a, 0xf0, 0x57], [0x21, 0xef, 0xb1, 0x4f], [0xa4, 0x48, 0xf6, 0xd9],
            [0x4d, 0x6d, 0xce, 0x24], [0xaa, 0x32, 0x63, 0x60], [0x11, 0x3b, 0x30, 0xe6],
            [0xa2, 0x5e, 0x7e, 0xd5], [0x83, 0xb1, 0xcf, 0x9a], [0x27, 0xf9, 0x39, 0x43],
            [0x6a, 0x94, 0xf7, 0x67], [0xc0, 0xa6, 0x94, 0x07], [0xd1, 0x9d, 0xa4, 0xe1],
            [0xec, 0x17, 0x86, 0xeb], [0x6f, 0xa6, 0x49, 0x71], [0x48, 0x5f, 0x70, 0x32],
            [0x22, 0xcb, 0x87, 0x55], [0xe2, 0x6d, 0x13, 0x52], [0x33, 0xf0, 0xb7, 0xb3],
            [0x40, 0xbe, 0xeb, 0x28], [0x2f, 0x18, 0xa2, 0x59], [0x67, 0x47, 0xd2, 0x6b],
            [0x45, 0x8c, 0x55, 0x3e], [0xa7, 0xe1, 0x46, 0x6c], [0x94, 0x11, 0xf1, 0xdf],
            [0x82, 0x1f, 0x75, 0x0a], [0xad, 0x07, 0xd7, 0x53], [0xca, 0x40, 0x05, 0x38],
            [0x8f, 0xcc, 0x50, 0x06], [0x28, 0x2d, 0x16, 0x6a], [0xbc, 0x3c, 0xe7, 0xb5],
            [0xe9, 0x8b, 0xa0, 0x6f], [0x44, 0x8c, 0x77, 0x3c], [0x8e, 0xcc, 0x72, 0x04],
            [0x01, 0x00, 0x22, 0x02]
        ];

        let key = Aes192Key::from(key_bytes);
        let expanded_key = Aes192::key_expansion(&key);
        
        assert_eq!(expanded_key, expected_w);
    }

    /// Test vector from NIST SP 800-38A, Appendix F.3 (for AES-192)
    #[test]
    fn aes192_nist_sp800_38a_appendix_f3() {
        let key_bytes: [u8; 24] = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];

        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];

        let expected_ciphertext: [u8; 16] = [
            0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
            0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
        ];
        
        let mut block = plaintext;

        // Create the cipher instance
        let key = Aes192Key::from(key_bytes);
        let cipher = Aes192::new(&key);

        // 1. Encrypt the block
        cipher.encrypt_block(&mut block);
        assert_eq!(block, expected_ciphertext, "Encryption output mismatch!");

        // 2. Decrypt the block
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext, "Decryption failed to restore original plaintext!");
    }
}

