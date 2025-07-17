use super::consts::{S_BOX, INV_S_BOX};

#[inline]
pub(super) fn add_round_key(state: &mut [u8; 16], round_key: &[[u8; 4]; 4]) {
    for (i, byte) in state.iter_mut().enumerate() {
        let col = i / 4;
        let row = i % 4;
        *byte ^= round_key[col][row];
    }
}

#[inline]
pub(super) fn sub_bytes(state: &mut [u8; 16]) {
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
pub(super) fn shift_rows(state: &mut [u8; 16]) {
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
pub(super) fn mix_columns(state: &mut [u8; 16]) {
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
        let t0 = xtime(s0);
        let t1 = xtime(s1);
        let t2 = xtime(s2);
        let t3 = xtime(s3);
        state[base] = t0 ^ (t1 ^ s1) ^ s2 ^ s3;
        state[base + 1] = s0 ^ t1 ^ (t2 ^ s2) ^ s3;
        state[base + 2] = s0 ^ s1 ^ t2 ^ (t3 ^ s3);
        state[base + 3] = (t0 ^ s0) ^ s1 ^ s2 ^ t3;
    }
}

#[inline]
pub(super) fn inv_sub_bytes(state: &mut [u8; 16]) {
    state[0] = INV_S_BOX[state[0] as usize];
    state[1] = INV_S_BOX[state[1] as usize];
    state[2] = INV_S_BOX[state[2] as usize];
    state[3] = INV_S_BOX[state[3] as usize];
    state[4] = INV_S_BOX[state[4] as usize];
    state[5] = INV_S_BOX[state[5] as usize];
    state[6] = INV_S_BOX[state[6] as usize];
    state[7] = INV_S_BOX[state[7] as usize];
    state[8] = INV_S_BOX[state[8] as usize];
    state[9] = INV_S_BOX[state[9] as usize];
    state[10] = INV_S_BOX[state[10] as usize];
    state[11] = INV_S_BOX[state[11] as usize];
    state[12] = INV_S_BOX[state[12] as usize];
    state[13] = INV_S_BOX[state[13] as usize];
    state[14] = INV_S_BOX[state[14] as usize];
    state[15] = INV_S_BOX[state[15] as usize];
}

#[inline]
pub(super) fn inv_shift_rows(state: &mut [u8; 16]) {
    // Row 1: right shift 1
    // [s11, s12, s13, s10] -> [s10, s11, s12, s13]
    // state indices: 1, 5, 9, 13
    let temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Row 2: right shift 2
    // [s22, s23, s20, s21] -> [s20, s21, s22, s23]
    // state indices: 2, 6, 10, 14
    let temp1 = state[10];
    let temp2 = state[14];
    state[10] = state[2];
    state[14] = state[6];
    state[2] = temp1;
    state[6] = temp2;

    // Row 3: right shift 3 (equivalent to left shift 1)
    // [s33, s30, s31, s32] -> [s30, s31, s32, s33]
    // state indices: 3, 7, 11, 15
    let temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

#[inline]
pub(super) fn inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let base = c * 4;
        let s0 = state[base];
        let s1 = state[base + 1];
        let s2 = state[base + 2];
        let s3 = state[base + 3];

        // Precompute basic multiplication
        let t0_2 = xtime(s0);           // 02 * s0
        let t0_4 = xtime(t0_2);         // 04 * s0
        let t0_8 = xtime(t0_4);         // 08 * s0
        
        let t1_2 = xtime(s1);           // 02 * s1
        let t1_4 = xtime(t1_2);         // 04 * s1
        let t1_8 = xtime(t1_4);         // 08 * s1
        
        let t2_2 = xtime(s2);           // 02 * s2
        let t2_4 = xtime(t2_2);         // 04 * s2
        let t2_8 = xtime(t2_4);         // 08 * s2
        
        let t3_2 = xtime(s3);           // 02 * s3
        let t3_4 = xtime(t3_2);         // 04 * s3
        let t3_8 = xtime(t3_4);         // 08 * s3

        // Construct the required multiplication result
        let s0_0e = t0_8 ^ t0_4 ^ t0_2;       // 0E * s0
        let s0_0b = t0_8 ^ t0_2 ^ s0;         // 0B * s0
        let s0_0d = t0_8 ^ t0_4 ^ s0;         // 0D * s0
        let s0_09 = t0_8 ^ s0;                // 09 * s0

        let s1_0e = t1_8 ^ t1_4 ^ t1_2;       // 0E * s1
        let s1_0b = t1_8 ^ t1_2 ^ s1;         // 0B * s1
        let s1_0d = t1_8 ^ t1_4 ^ s1;         // 0D * s1
        let s1_09 = t1_8 ^ s1;                // 09 * s1

        let s2_0e = t2_8 ^ t2_4 ^ t2_2;       // 0E * s2
        let s2_0b = t2_8 ^ t2_2 ^ s2;         // 0B * s2
        let s2_0d = t2_8 ^ t2_4 ^ s2;         // 0D * s2
        let s2_09 = t2_8 ^ s2;                // 09 * s2

        let s3_0e = t3_8 ^ t3_4 ^ t3_2;       // 0E * s3
        let s3_0b = t3_8 ^ t3_2 ^ s3;         // 0B * s3
        let s3_0d = t3_8 ^ t3_4 ^ s3;         // 0D * s3
        let s3_09 = t3_8 ^ s3;                // 09 * s3

        // Based on the FIPS 197 formulas (5.15), we calculate the new column values.
        // s'0 = {0e}*s0 + {0b}*s1 + {0d}*s2 + {09}*s3
        // s'1 = {09}*s0 + {0e}*s1 + {0b}*s2 + {0d}*s3
        // s'2 = {0d}*s0 + {09}*s1 + {0e}*s2 + {0b}*s3
        // s'3 = {0b}*s0 + {0d}*s1 + {09}*s2 + {0e}*s3
        state[base] = s0_0e ^ s1_0b ^ s2_0d ^ s3_09;
        state[base + 1] = s0_09 ^ s1_0e ^ s2_0b ^ s3_0d;
        state[base + 2] = s0_0d ^ s1_09 ^ s2_0e ^ s3_0b;
        state[base + 3] = s0_0b ^ s1_0d ^ s2_09 ^ s3_0e;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A round-trip test for add_round_key, verifying it's its own inverse.
    #[test]
    fn aes_add_round_key_roundtrip() {
        let mut state: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let original_state = state;

        let round_key: [[u8; 4]; 4] = [
            [0x2b, 0x7e, 0x15, 0x16],
            [0x28, 0xae, 0xd2, 0xa6],
            [0xab, 0xf7, 0x15, 0x88],
            [0x09, 0xcf, 0x4f, 0x3c],
        ];

        // Apply the function once
        add_round_key(&mut state, &round_key);
        // The state should have changed
        assert_ne!(state, original_state);

        // Apply the function again with the same key
        add_round_key(&mut state, &round_key);
        // The state should be restored to its original value
        assert_eq!(state, original_state);
    }

    /// A round-trip test for SubBytes and InvSubBytes.
    #[test]
    fn aes_sub_bytes_roundtrip() {
        let mut state: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let original_state = state;

        sub_bytes(&mut state);
        inv_sub_bytes(&mut state);

        assert_eq!(state, original_state);
    }

    /// A round-trip test for ShiftRows and InvShiftRows.
    #[test]
    fn aes_shift_rows_roundtrip() {
        let mut state: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let original_state = state;

        shift_rows(&mut state);
        inv_shift_rows(&mut state);

        assert_eq!(state, original_state);
    }
    
    /// Test MixColumns against the official FIPS-197 Appendix B vector.
    #[test]
    fn aes_fips_197_mix_columns() {
        // State after ShiftRows in Round 1 of Appendix B
        let mut state: [u8; 16] = [
            0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae,
            0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5,
        ];

        // Expected state after MixColumns
        let expected_state: [u8; 16] = [
            0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a,
            0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c,
        ];
        
        mix_columns(&mut state);
        
        assert_eq!(state, expected_state);
    }
    
    /// Test InvMixColumns by reversing the official FIPS-197 Appendix B vector.
    #[test]
    fn aes_fips_197_inv_mix_columns() {
        // State after MixColumns in Round 1 of Appendix B
        let mut state: [u8; 16] = [
            0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a,
            0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c,
        ];

        // Expected state is the state *before* MixColumns (i.e., after ShiftRows)
        let expected_state: [u8; 16] = [
            0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae,
            0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5,
        ];
        
        inv_mix_columns(&mut state);
        
        assert_eq!(state, expected_state);
    }
}