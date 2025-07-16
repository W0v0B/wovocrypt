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

    #[inline]
    fn add_round_key(state: &mut [u8; 16], round_key: &[[u8; 4]; 4]) {
        for (i, byte) in state.iter_mut().enumerate() {
            let col = i / 4;
            let row = i % 4;
            *byte ^= round_key[col][row];
        }
    }

    #[inline]
    fn sub_bytes(state: &mut [u8; 16]) {
        state[0] = S_BOX[state[0] as usize];
        state[1] = S_BOX[state[1] as usize];
        state[2] = S_BOX[state[2] as usize];
        state[3] = S_BOX[state[3] as usize];
        state[4] = S_BOX[state[4] as usize];
        state[5] = S_BOX[state[5] as usize];
        state[6] = S_BOX[state[6] as usize];
        state[7] = S_BOX[state[7] as usize];
        state[8] = S_BOX[state[8] as usize];
        state[9] = S_BOX[state[9] as usize];
        state[10] = S_BOX[state[10] as usize];
        state[11] = S_BOX[state[11] as usize];
        state[12] = S_BOX[state[12] as usize];
        state[13] = S_BOX[state[13] as usize];
        state[14] = S_BOX[state[14] as usize];
        state[15] = S_BOX[state[15] as usize];
    }

    #[inline]
    fn shift_rows(state: &mut [u8; 16]) {
        // Row 1: left shift 1
        // [s10, s11, s12, s13] -> [s11, s12, s13, s10]
        // state indices: 1, 5, 9, 13
        let temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;

        // Row 2: left shift 2
        // [s20, s21, s22, s23] -> [s22, s23, s20, s21]
        // state indices: 2, 6, 10, 14
        let temp1 = state[2];
        let temp2 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = temp1;
        state[14] = temp2;

        // Row 3: left shift 3 (equivalent to right shift 1)
        // [s30, s31, s32, s33] -> [s33, s30, s31, s32]
        // state indices: 3, 7, 11, 15
        let temp = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp;
    }

    #[inline]
    fn xtime(b: u8) -> u8 {
        (b << 1) ^ (((b >> 7) & 1) * 0x1B)
    }

    #[inline]
    fn mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            // Get the current column
            let base = c * 4;
            let s0 = state[base];
            let s1 = state[base + 1];
            let s2 = state[base + 2];
            let s3 = state[base + 3];

            // Perform the matrix multiplication in GF(2^8)
            // {02}*s0 + {03}*s1 + {01}*s2 + {01}*s3
            // {01}*s0 + {02}*s1 + {03}*s2 + {01}*s3
            // {01}*s0 + {01}*s1 + {02}*s2 + {03}*s3
            // {03}*s0 + {01}*s1 + {01}*s2 + {02}*s3
            let t0 = Self::xtime(s0);
            let t1 = Self::xtime(s1);
            let t2 = Self::xtime(s2);
            let t3 = Self::xtime(s3);
            state[base] = t0 ^ (t1 ^ s1) ^ s2 ^ s3;
            state[base + 1] = s0 ^ t1 ^ (t2 ^ s2) ^ s3;
            state[base + 2] = s0 ^ s1 ^ t2 ^ (t3 ^ s3);
            state[base + 3] = (t0 ^ s0) ^ s1 ^ s2 ^ t3;
        }
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
        Self::add_round_key(&mut state, &self.get_round_key(0));

        // --- 9 Main Rounds ---
        for round in 1..=9 {
            // replace the bytes with S_BOX
            Self::sub_bytes(&mut state);
            // row shift
            Self::shift_rows(&mut state);
            // column confusion
            Self::mix_columns(&mut state);
            // key injection
            Self::add_round_key(&mut state, &self.get_round_key(round));
        }

        // --- Last Round (omits column confusion) ---
        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &self.get_round_key(10));

        *block = state;
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test vector from FIPS-197, Appendix B.
    #[test]
    fn fips_197_appendix_b() {
        // The test key from Appendix B
        let key_bytes: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];

        // The plaintext block from Appendix B
        let mut block: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];

        // The expected ciphertext from Appendix B
        let expected_ciphertext: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ];

        // Create the cipher instance
        let key = Aes128Key::from(key_bytes);
        let cipher = Aes128::new(&key);

        // Encrypt the block
        cipher.encrypt_block(&mut block);

        // Assert that the encrypted block matches the expected ciphertext
        assert_eq!(block, expected_ciphertext);
    }
}

