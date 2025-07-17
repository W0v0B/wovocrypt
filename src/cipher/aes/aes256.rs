use zeroize::Zeroize;
use super::BlockCipher;
use super::consts::{S_BOX, RCON};
use super::internal::{add_round_key, sub_bytes, shift_rows, mix_columns,
    inv_sub_bytes, inv_shift_rows, inv_mix_columns};

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

impl Aes256 {
    fn key_expansion(key: &self::Aes256Key) -> [[u8; 4]; 60] {
        // create 60 word array
        let mut w = [[0u8; 4]; 60];
        let nk = 8; // For AES-256, Nk = 8 words
        let mut rcon_index = 0;

        // copy key into the first Nk words
        w[0].copy_from_slice(&key.as_ref()[0..4]);
        w[1].copy_from_slice(&key.as_ref()[4..8]);
        w[2].copy_from_slice(&key.as_ref()[8..12]);
        w[3].copy_from_slice(&key.as_ref()[12..16]);
        w[4].copy_from_slice(&key.as_ref()[16..20]);
        w[5].copy_from_slice(&key.as_ref()[20..24]);
        w[6].copy_from_slice(&key.as_ref()[24..28]);
        w[7].copy_from_slice(&key.as_ref()[28..32]);

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

            // For AES-256, if i % nk == 4, an extra SubWord is applied.
            } else if i % nk == 4 { // nk is 8 for AES-256
                let mut bytes = temp.to_be_bytes();
                for byte in &mut bytes {
                    *byte = S_BOX[*byte as usize];
                }
                temp = u32::from_be_bytes(bytes);
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

impl BlockCipher for Aes256 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 32;
    type Block = [u8; 16];
    type Key = Aes256Key;

    fn new(key: &Self::Key) -> Self {
        Self { expanded_key: Self::key_expansion(key) }
    }

    fn encrypt_block(&self, block: &mut Self::Block) {
        let mut state = *block;

        // --- First Round ---
        // key injection
        add_round_key(&mut state, &self.get_round_key(0));

        // --- 13 Main Rounds ---
        for round in 1..=13 {
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
        add_round_key(&mut state, &self.get_round_key(14));

        *block = state;
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        let mut state = *block;

        // --- First Round (from ciphertext) ---
        // decrypt the last round of encrypt block
        add_round_key(&mut state, &self.get_round_key(14));

        // --- 13 Main Rounds (in reverse order) ---
        for round in (1..=13).rev() {
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

    /// Test the key expansion against the official FIPS-197 Appendix A.3 vector.
    #[test]
    fn fips_197_key_expansion_a3() {
        // The test key from Appendix A.3
        let key_bytes: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
            0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];

        // The expected expanded key words from FIPS-197, Appendix A.3
        // This has been corrected to contain exactly 60 words.
        let expected_w: [[u8; 4]; 60] = [
            [0x60, 0x3d, 0xeb, 0x10], [0x15, 0xca, 0x71, 0xbe], [0x2b, 0x73, 0xae, 0xf0], [0x85, 0x7d, 0x77, 0x81],
            [0x1f, 0x35, 0x2c, 0x07], [0x3b, 0x61, 0x08, 0xd7], [0x2d, 0x98, 0x10, 0xa3], [0x09, 0x14, 0xdf, 0xf4],
            [0x9b, 0xa3, 0x54, 0x11], [0x8e, 0x69, 0x25, 0xaf], [0xa5, 0x1a, 0x8b, 0x5f], [0x20, 0x67, 0xfc, 0xde],
            [0xa8, 0xb0, 0x9c, 0x1a], [0x93, 0xd1, 0x94, 0xcd], [0xbe, 0x49, 0x84, 0x6e], [0xb7, 0x5d, 0x5b, 0x9a],
            [0xd5, 0x9a, 0xec, 0xb8], [0x5b, 0xf3, 0xc9, 0x17], [0xfe, 0xe9, 0x42, 0x48], [0xde, 0x8e, 0xbe, 0x96],
            [0xb5, 0xa9, 0x32, 0x8a], [0x26, 0x78, 0xa6, 0x47], [0x98, 0x31, 0x22, 0x29], [0x2f, 0x6c, 0x79, 0xb3],
            [0x81, 0x2c, 0x81, 0xad], [0xda, 0xdf, 0x48, 0xba], [0x24, 0x36, 0x0a, 0xf2], [0xfa, 0xb8, 0xb4, 0x64],
            [0x98, 0xc5, 0xbf, 0xc9], [0xbe, 0xbd, 0x19, 0x8e], [0x26, 0x8c, 0x3b, 0xa7], [0x09, 0xe0, 0x42, 0x14],
            [0x68, 0x00, 0x7b, 0xac], [0xb2, 0xdf, 0x33, 0x16], [0x96, 0xe9, 0x39, 0xe4], [0x6c, 0x51, 0x8d, 0x80],
            [0xc8, 0x14, 0xe2, 0x04], [0x76, 0xa9, 0xfb, 0x8a], [0x50, 0x25, 0xc0, 0x2d], [0x59, 0xc5, 0x82, 0x39],
            [0xde, 0x13, 0x69, 0x67], [0x6c, 0xcc, 0x5a, 0x71], [0xfa, 0x25, 0x63, 0x95], [0x96, 0x74, 0xee, 0x15],
            [0x58, 0x86, 0xca, 0x5d], [0x2e, 0x2f, 0x31, 0xd7], [0x7e, 0x0a, 0xf1, 0xfa], [0x27, 0xcf, 0x73, 0xc3],
            [0x74, 0x9c, 0x47, 0xab], [0x18, 0x50, 0x1d, 0xda], [0xe2, 0x75, 0x7e, 0x4f], [0x74, 0x01, 0x90, 0x5a],
            [0xca, 0xfa, 0xaa, 0xe3], [0xe4, 0xd5, 0x9b, 0x34], [0x9a, 0xdf, 0x6a, 0xce], [0xbd, 0x10, 0x19, 0x0d],
            [0xfe, 0x48, 0x90, 0xd1], [0xe6, 0x18, 0x8d, 0x0b], [0x04, 0x6d, 0xf3, 0x44], [0x70, 0x6c, 0x63, 0x1e]
        ];

        let key = Aes256Key::from(key_bytes);
        let expanded_key = Aes256::key_expansion(&key);
        
        assert_eq!(expanded_key, expected_w);
    }

    /// Test vector from NIST SP 800-38A, Appendix F.1.5 (for AES-256)
    #[test]
    fn aes256_nist_sp800_38a_appendix_f1_5() {
        let key_bytes: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];

        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];

        let expected_ciphertext: [u8; 16] = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
        ];
        
        let mut block = plaintext;

        // Create the cipher instance
        let key = Aes256Key::from(key_bytes);
        let cipher = Aes256::new(&key);

        // 1. Encrypt the block
        cipher.encrypt_block(&mut block);
        assert_eq!(block, expected_ciphertext, "Encryption output mismatch!");

        // 2. Decrypt the block
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext, "Decryption failed to restore original plaintext!");
    }
}

