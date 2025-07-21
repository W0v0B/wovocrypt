use zeroize::Zeroize;
use super::super::BlockCipher;
use super::consts::{S_BOX, RCON};
use super::internal::{add_round_key, sub_bytes, shift_rows, mix_columns,
    inv_sub_bytes, inv_shift_rows, inv_mix_columns};

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

#[derive(Zeroize, Clone)]
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

impl BlockCipher for Aes128 {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 16;
    type Block = [u8; 16];
    type Key = Aes128Key;

    fn new(key: &Self::Key) -> Self {
        Self { expanded_key: Self::key_expansion(key) }
    }

    fn encrypt_block(&self, block: &mut Self::Block) {
        let mut state = *block;

        // --- First Round ---
        // key injection
        add_round_key(&mut state, &self.get_round_key(0));

        // --- 9 Main Rounds ---
        for round in 1..=9 {
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
        add_round_key(&mut state, &self.get_round_key(10));

        *block = state;
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        let mut state = *block;

        // --- First Round (from ciphertext) ---
        // decrypt the last round of encrypt block
        add_round_key(&mut state, &self.get_round_key(10));

        // --- 9 Main Rounds (in reverse order) ---
        for round in (1..=9).rev() {
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

    /// Test the key expansion against the official FIPS-197 Appendix A.1 vector.
    #[test]
    fn fips_197_key_expansion_a1() {
        // The test key from Appendix A.1
        let key_bytes: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];

        // The expected expanded key words from the FIPS-197 document
        let expected_w: [[u8; 4]; 44] = [
            [0x2b, 0x7e, 0x15, 0x16], [0x28, 0xae, 0xd2, 0xa6], [0xab, 0xf7, 0x15, 0x88], [0x09, 0xcf, 0x4f, 0x3c],
            [0xa0, 0xfa, 0xfe, 0x17], [0x88, 0x54, 0x2c, 0xb1], [0x23, 0xa3, 0x39, 0x39], [0x2a, 0x6c, 0x76, 0x05],
            [0xf2, 0xc2, 0x95, 0xf2], [0x7a, 0x96, 0xb9, 0x43], [0x59, 0x35, 0x80, 0x7a], [0x73, 0x59, 0xf6, 0x7f],
            [0x3d, 0x80, 0x47, 0x7d], [0x47, 0x16, 0xfe, 0x3e], [0x1e, 0x23, 0x7e, 0x44], [0x6d, 0x7a, 0x88, 0x3b],
            [0xef, 0x44, 0xa5, 0x41], [0xa8, 0x52, 0x5b, 0x7f], [0xb6, 0x71, 0x25, 0x3b], [0xdb, 0x0b, 0xad, 0x00],
            [0xd4, 0xd1, 0xc6, 0xf8], [0x7c, 0x83, 0x9d, 0x87], [0xca, 0xf2, 0xb8, 0xbc], [0x11, 0xf9, 0x15, 0xbc],
            [0x6d, 0x88, 0xa3, 0x7a], [0x11, 0x0b, 0x3e, 0xfd], [0xdb, 0xf9, 0x86, 0x41], [0xca, 0x00, 0x93, 0xfd],
            [0x4e, 0x54, 0xf7, 0x0e], [0x5f, 0x5f, 0xc9, 0xf3], [0x84, 0xa6, 0x4f, 0xb2], [0x4e, 0xa6, 0xdc, 0x4f],
            [0xea, 0xd2, 0x73, 0x21], [0xb5, 0x8d, 0xba, 0xd2], [0x31, 0x2b, 0xf5, 0x60], [0x7f, 0x8d, 0x29, 0x2f],
            [0xac, 0x77, 0x66, 0xf3], [0x19, 0xfa, 0xdc, 0x21], [0x28, 0xd1, 0x29, 0x41], [0x57, 0x5c, 0x00, 0x6e],
            [0xd0, 0x14, 0xf9, 0xa8], [0xc9, 0xee, 0x25, 0x89], [0xe1, 0x3f, 0x0c, 0xc8], [0xb6, 0x63, 0x0c, 0xa6]
        ];

        let key = Aes128Key::from(key_bytes);
        let expanded_key = Aes128::key_expansion(&key);
        
        assert_eq!(expanded_key, expected_w);
    }

    /// Test vector from FIPS-197, Appendix B.
    #[test]
    fn aes128_fips_197_appendix_b() {
        let key_bytes: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];

        // Optional: Verify against the known ciphertext to make sure encryption still works
        let expected_ciphertext: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ];

        let mut block = plaintext;
        
        // Create the cipher instance
        let key = Aes128Key::from(key_bytes);
        let cipher = Aes128::new(&key);

        // 1. Encrypt the block
        cipher.encrypt_block(&mut block);
        assert_eq!(block, expected_ciphertext, "Encryption output mismatch!");

        // 2. Decrypt the block
        cipher.decrypt_block(&mut block);
        assert_eq!(block, plaintext, "Decryption failed to restore original plaintext!");
    }
}
