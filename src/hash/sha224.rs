use crate::hash::Hasher;
use zeroize::Zeroize;

const H0: [u32; 8] = [
    0xc1059ed8, 0x367cd507,
    0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511,
    0x64f98fa7, 0xbefa4fa4
];

#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
pub struct Sha224Output([u8; 28]);
impl AsRef<[u8]> for Sha224Output {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for Sha224Output {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl From<[u8; 28]> for Sha224Output {
    fn from(array: [u8; 28]) -> Self {
        Self(array)
    }
}
impl From<Sha224Output> for [u8; 28] {
    fn from(output: Sha224Output) -> [u8; 28] {
        output.0
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Sha224Block([u8; 64]);
impl Default for Sha224Block {
    fn default() -> Self {
        Sha224Block([0u8; 64])
    }
}
impl AsRef<[u8]> for Sha224Block {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for Sha224Block {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl From<[u8; 64]> for Sha224Block {
    fn from(array: [u8; 64]) -> Self {
        Self(array)
    }
}
impl From<Sha224Block> for [u8; 64] {
    fn from(output: Sha224Block) -> [u8; 64] {
        output.0
    }
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Sha224 {
    state: [u32; 8],
    length: u64,
    buffer: [u8; 64]
}

impl Default for Sha224 {
    fn default() -> Self {
        Sha224 {
            state: H0,
            length: 0,
            buffer: [0; 64]
        }
    }
}

impl Sha224 {
    pub const BLOCK_SIZE: usize = 64;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Same as SHA256
    fn process_block(&mut self, block: &[u8; Self::BLOCK_SIZE])
    {
        let mut w: [u32; 64] = [0; 64];

        // block in big-endian for w first 16 byte.
        for t in 0..16 {
            let start = t * 4;
            w[t] = u32::from_be_bytes(block[start..start + 4].try_into().unwrap());
        }
        // next 48 bytes
        // σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
        // σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
        // W[t] = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]
        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
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

        for t in 0..64 {
            // Ch(x,y,z) = (x & y) ^ (!x & z)
            let ch = (e & f) ^ (!e & g);

            // Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
            let maj = (a & b) ^ (a & c) ^ (b & c);

            // Σ₀(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);

            // Σ₁(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);

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

impl Hasher for Sha224 {
    const OUTPUT_SIZE: usize = 28;
    type HashBlock = Sha224Block;
    type Output = Sha224Output;

    fn update(&mut self, input: &[u8]) {
        let buffer_pos = (self.length % Self::BLOCK_SIZE as u64) as usize;
        let mut input_pos = 0;

        // update self.length
        self.length = self.length.saturating_add(input.len() as u64);

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
        let buffer_pos = (self.length % Self::BLOCK_SIZE as u64) as usize;

        // Append '1' bit (0x80)
        self.buffer[buffer_pos] = 0x80;
        
        // padding '0'
        if buffer_pos + 1 > Self::BLOCK_SIZE - 8 {
            // process second to last block
            self.buffer[(buffer_pos + 1)..].fill(0);
            let block = self.buffer;
            self.process_block(&block);
            self.buffer.fill(0);
        } else {
            self.buffer[(buffer_pos + 1)..(Self::BLOCK_SIZE - 8)].fill(0);
        }

        // padding total data length in last 8 bytes
        let total_bits = self.length * 8;
        let len_bytes = total_bits.to_be_bytes();
        self.buffer[(Self::BLOCK_SIZE - 8)..].copy_from_slice(&len_bytes);

        // process last block
        let block = self.buffer;
        self.process_block(&block);

        // out hash
        let mut result = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            let bytes = word.to_be_bytes();
            result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        Sha224Output(result[..28].try_into().unwrap())
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sha224_output_conversions() {
        let array = [1u8; 28];
        let output = Sha224Output::from(array);
        let back_to_array: [u8; 28] = output.into();
        assert_eq!(array, back_to_array);
    }

    #[test]
    fn test_sha224_output_as_ref_mut() {
        let mut output = Sha224Output::default();
        output.as_mut()[0] = 42;
        assert_eq!(output.as_ref()[0], 42);
    }

    #[test]
    fn test_sha224_block_conversions() {
        let array = [1u8; 64];
        let output = Sha224Block::from(array);
        let back_to_array: [u8; 64] = output.into();
        assert_eq!(array, back_to_array);
    }

    #[test]
    fn test_sha224_block_as_ref_mut() {
        let mut output = Sha224Block::default();
        output.as_mut()[0] = 42;
        assert_eq!(output.as_ref()[0], 42);
    }

    #[test]
    fn test_sha224_initial_state() {
        let hasher = Sha224::default();
        assert_eq!(hasher.state, H0);
        assert_eq!(hasher.length, 0);
        assert_eq!(hasher.buffer, [0u8; 64]);
    }

    #[test]
    fn test_single_block_processing() {
        let mut hasher = Sha224::default();
        let mut block = [0u8; 64];
        block[0] = 0x80;
        hasher.process_block(&block);
        
        // Check that state changed from initial
        assert_ne!(hasher.state, H0);
    }

    #[test]
    fn test_length_tracking() {
        let mut hasher = Sha224::default();
        
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
        let mut hasher = Sha224::default();
        let data1 = vec![1u8; 30];
        hasher.update(&data1);
        assert_eq!(hasher.buffer[..30], data1[..]);
        assert_eq!(hasher.state, H0);
        
        // Add 40 more bytes (total 70, should trigger block processing)
        let data2 = vec![2u8; 40];
        hasher.update(&data2);
        assert_eq!(hasher.buffer[..6], vec![2u8; 6][..]);
        assert_ne!(hasher.state, H0);
    }

    #[test]
    fn test_reset_functionality() {
        let mut hasher = Sha224::default();
        hasher.update(b"secret");
        
        // Clone to test zeroize
        let mut hasher_clone = hasher.clone();
        hasher_clone.reset();
        
        // After zeroizing, should be back to default state
        let default_hasher = Sha224::default();
        assert_eq!(hasher_clone.state, default_hasher.state);
        assert_eq!(hasher_clone.length, default_hasher.length);
        assert_eq!(hasher_clone.buffer, default_hasher.buffer);
    }

    #[test]
    fn test_output_zeroize() {
        let mut output = Sha224Output::from([42u8; 28]);
        output.zeroize();
        assert_eq!(output.as_ref(), &[0u8; 28]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_large_length_handling() {
        let mut hasher = Sha224::default();
        
        // Test with large input that could cause overflow
        let large_data = vec![0u8; 1000];
        hasher.update(&large_data);
        assert_eq!(hasher.length, 1000);
        
        // Test saturating add behavior
        hasher.length = u64::MAX - 10;
        hasher.update(&[0u8; 20]); // This should saturate
        assert_eq!(hasher.length, u64::MAX);
    }
    
    #[test]
    fn test_block_size_constant() {
        assert_eq!(Sha224::BLOCK_SIZE, 64);
    }
}