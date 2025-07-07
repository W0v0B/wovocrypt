use crate::hash::Hasher;
use zeroize::Zeroize;

const H0: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
    0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
];

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Sha384Output([u8; 48]);

impl Default for Sha384Output {
    fn default() -> Self {
        Sha384Output([0u8; 48])
    }
}

impl AsRef<[u8]> for Sha384Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Sha384Output {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<[u8; 48]> for Sha384Output {
    fn from(array: [u8; 48]) -> Self {
        Self(array)
    }
}

impl From<Sha384Output> for [u8; 48] {
    fn from(output: Sha384Output) -> Self {
        output.0
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Sha384 {
    state: [u64; 8],
    length: u128,
    buffer: [u8; 128]
}

impl Default for Sha384 {
    fn default() -> Self {
        Sha384 {
            state: H0,
            length: 0,
            buffer: [0u8; 128]
        }
    }
}

impl Sha384 {
    pub const BLOCK_SIZE: usize = 128;

    const K: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ];

    // Same as SHA512
    fn process_block(&mut self, block: &[u8; Self::BLOCK_SIZE]) {
        let mut w = [0u64; 80];

        // block in big-endian for w first 16 byte.
        for t in 0..16 {
            let start = t * 8;
            w[t] = u64::from_be_bytes(block[start..start + 8].try_into().unwrap());
        }
        // next 64 bytes
        // σ₀(x) = ROTR¹(x) ⊕ ROTR⁸(x) ⊕ SHR⁷(x)
        // σ₁(x) = ROTR¹⁹(x) ⊕ ROTR⁶¹(x) ⊕ SHR⁶(x)
        // Wt = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]
        for t in 16..80 {
            let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
            let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }

        // Initialize the eight working variables
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for t in 0..80 {
            // Ch(e,f,g) = (e & f) ⊕ (!e & g)
            let ch = (e & f) ^ (!e & g);

            // Maj(a,b,c) = (a & b) ⊕ (a & c) ⊕ (b & c)
            let maj = (a & b) ^ (a & c) ^ (b & c);

            // Σ₀(a) = ROTR²⁸(a) ⊕ ROTR³⁴(a) ⊕ ROTR³⁹(a)
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);

            // Σ₁(e) = ROTR¹⁴(e) ⊕ ROTR¹⁸(e) ⊕ ROTR⁴¹(e)
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);

            // T₁ = h + Σ₁(e) + Ch(e,f,g) + K[t] + W[t]
            let t1 = h.wrapping_add(s1)
                         .wrapping_add(ch)
                         .wrapping_add(Self::K[t])
                         .wrapping_add(w[t]);

            // T₂ = Σ₀(a) + Maj(a,b,c)
            let t2 = s0.wrapping_add(maj);

            // Data Exchange
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // update state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Hasher for Sha384 {
    const OUTPUT_SIZE: usize = 64;
    type Output = Sha384Output;

    fn update(&mut self, input: &[u8]) {
        let buffer_pos = (self.length % Self::BLOCK_SIZE as u128) as usize;
        let mut input_pos = 0;

        // update self.length
        self.length = self.length.saturating_add(input.len() as u128);

        // process last time remaining input
        if buffer_pos > 0 {
            let remaining_len = Self::BLOCK_SIZE - buffer_pos;
            if remaining_len > input.len() {
                self.buffer[buffer_pos..buffer_pos + input.len()].copy_from_slice(input);
                return;
            } else {
                self.buffer[buffer_pos..Self::BLOCK_SIZE].copy_from_slice(&input[..remaining_len]);
                let block = self.buffer;
                self.process_block(&block);
                input_pos += remaining_len;
            }
        }

        // process input
        while input_pos + Self::BLOCK_SIZE <= input.len() {
            let block = &input[input_pos..input_pos + Self::BLOCK_SIZE];
            self.process_block(block.try_into().unwrap());
            input_pos += Self::BLOCK_SIZE;
        }

        // process remaining input
        let remaining_input = &input[input_pos..];
        if !remaining_input.is_empty() {
            self.buffer[..remaining_input.len()].copy_from_slice(remaining_input);
        }
    }

    fn finalize(mut self) -> Self::Output where Self: Sized {
        let buffer_pos = (self.length % Self::BLOCK_SIZE as u128) as usize;

        // Append '1' bit (0x80)
        self.buffer[buffer_pos] = 0x80;
        
        // padding '0'
        if buffer_pos + 1 > Self::BLOCK_SIZE - 16 {
            // process second to last block
            self.buffer[(buffer_pos + 1)..].fill(0);
            let block = self.buffer;
            self.process_block(&block);
            self.buffer.fill(0);
        } else {
            self.buffer[(buffer_pos + 1)..(Self::BLOCK_SIZE - 16)].fill(0);
        }

        // padding total data length in last 8 bytes
        let total_bits = self.length * 8;
        let len_bytes = total_bits.to_be_bytes();
        self.buffer[(Self::BLOCK_SIZE - 16)..].copy_from_slice(&len_bytes);

        // process last block
        let block = self.buffer;
        self.process_block(&block);

        // out hash
        let mut result = [0u8; 64];
        for (i, word) in self.state.iter().enumerate() {
            let bytes = word.to_be_bytes();
            result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }
        Sha384Output(result[..48].try_into().unwrap())
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sha384_output_conversions() {
        let array = [1u8; 48];
        let output = Sha384Output::from(array);
        let back_to_array: [u8; 48] = output.into();
        assert_eq!(array, back_to_array);
    }

    #[test]
    fn test_sha384_output_as_ref_mut() {
        let mut output = Sha384Output::default();
        output.as_mut()[0] = 42;
        assert_eq!(output.as_ref()[0], 42);
    }

    #[test]
    fn test_sha384_initial_state() {
        let hasher = Sha384::default();
        assert_eq!(hasher.state, H0);
        assert_eq!(hasher.length, 0);
        assert_eq!(hasher.buffer, [0u8; 128]);
    }

    #[test]
    fn test_single_block_processing() {
        let mut hasher = Sha384::default();
        let mut block = [0u8; 128];
        block[0] = 0x80;
        hasher.process_block(&block);
        
        // Check that state changed from initial
        assert_ne!(hasher.state, H0);
    }

    #[test]
    fn test_length_tracking() {
        let mut hasher = Sha384::default();
        
        hasher.update(b"abc");
        assert_eq!(hasher.length, 3);
        
        hasher.update(b"def");
        assert_eq!(hasher.length, 6);
        
        hasher.update(&[0u8; 100]);
        assert_eq!(hasher.length, 106);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_buffer_management() {
        let mut hasher = Sha384::default();
        let data1 = vec![1u8; 100];
        hasher.update(&data1);
        assert_eq!(hasher.buffer[..100], data1[..]);
        assert_eq!(hasher.state, H0);
        
        // Add 30 more bytes (total 130, should trigger block processing)
        let data2 = vec![2u8; 30];
        hasher.update(&data2);
        assert_eq!(hasher.buffer[..2], vec![2u8; 2][..]);
        assert_ne!(hasher.state, H0);
    }

    #[test]
    fn test_reset_functionality() {
        let mut hasher = Sha384::default();
        hasher.update(b"secret");
        
        // Clone to test zeroize
        let mut hasher_clone = hasher.clone();
        hasher_clone.reset();
        
        // After zeroizing, should be back to default state
        let default_hasher = Sha384::default();
        assert_eq!(hasher_clone.state, default_hasher.state);
        assert_eq!(hasher_clone.length, default_hasher.length);
        assert_eq!(hasher_clone.buffer, default_hasher.buffer);
    }

    #[test]
    fn test_output_zeroize() {
        let mut output = Sha384Output::from([42u8; 48]);
        output.zeroize();
        assert_eq!(output.as_ref(), &[0u8; 48]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_large_length_handling() {
        let mut hasher = Sha384::default();
        
        // Test with large input that could cause overflow
        let large_data = vec![0u8; 1000];
        hasher.update(&large_data);
        assert_eq!(hasher.length, 1000);
        
        // Test saturating add behavior
        hasher.length = u128::MAX - 10;
        hasher.update(&[0u8; 20]); // This should saturate
        assert_eq!(hasher.length, u128::MAX);
    }
    
    #[test]
    fn test_block_size_constant() {
        assert_eq!(Sha384::BLOCK_SIZE, 128);
    }
}