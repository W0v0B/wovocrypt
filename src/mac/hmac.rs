use crate::mac::Mac;
use crate::hash::Hasher;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
pub struct Hmac<H: Hasher> {
    inner_hasher: H,
    outer_hasher: H,
    processed_key: H::HashBlock
}

impl<H: Hasher> Hmac<H> {
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    fn process_key(key: &[u8]) -> H::HashBlock {
        // Hash block with all 0
        let mut processed_key = H::HashBlock::default();
        
        if key.len() > H::BLOCK_SIZE {
            // keys longer than H::BLOCK_SIZE bytes are first hashed using H
            let hash_result = H::compute(key);

            // Copy the hashed result into the block
            let hash_bytes = hash_result.as_ref();
            processed_key.as_mut()[..hash_bytes.len()].copy_from_slice(hash_bytes);
        } else {
            // In other cases copy directly
            processed_key.as_mut()[..key.len()].copy_from_slice(key);
        }

        processed_key
    }
}

impl<H: Hasher> Mac for Hmac<H> {
    const OUTPUT_SIZE: usize = H::OUTPUT_SIZE;
    type Output = H::Output;
    type Key = [u8];

    fn new(key: &Self::Key) -> Self {
        // process key
        let processed_key = Self::process_key(key);
        let mut inner_padded_key = processed_key.clone();
        let mut outer_padded_key = processed_key.clone();
        for i in 0..H::BLOCK_SIZE {
            // (K' ⊕ ipad)
            inner_padded_key.as_mut()[i] ^= Self::IPAD;
            // (K' ⊕ opad)
            outer_padded_key.as_mut()[i] ^= Self::OPAD;
        }

        // init inner_hasher H(K' ⊕ ipad)
        let mut inner_hasher = H::default();
        inner_hasher.update(inner_padded_key.as_ref());

        // init outer_hasher H(K' ⊕ opad)
        let mut outer_hasher = H::default();
        outer_hasher.update(outer_padded_key.as_ref());

        Self {
            inner_hasher: inner_hasher,
            outer_hasher: outer_hasher,
            processed_key: processed_key
        }
    }

    fn update(&mut self, input: &[u8]) {
        self.inner_hasher.update(input);
    }

    fn finalize(self) -> Self::Output where Self: Sized {
        // H( (K' ⊕ ipad) || m )
        let inner_hash = self.inner_hasher.finalize();

        // H(K' ⊕ opad) || H( (K' ⊕ ipad) || m )
        let mut outer_hasher = self.outer_hasher;
        outer_hasher.update(inner_hash.as_ref());

        outer_hasher.finalize()
    }

    fn reset(&mut self) {
        // reset inner_hasher
        self.inner_hasher.reset();

        // load key
        let mut inner_padded_key = self.processed_key.clone();
        for byte in inner_padded_key.as_mut() {
            *byte ^= Self::IPAD;
        }
        self.inner_hasher.update(inner_padded_key.as_ref());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hash::prelude::*;

    #[test]
    fn test_hmac_process_key_short() {
        let key = b"short_key";
        let processed = Hmac::<Sha256>::process_key(key);

        // First part should match the key
        assert_eq!(&processed.as_ref()[..key.len()], key);
        // Rest should be zeros
        for &byte in &processed.as_ref()[key.len()..] {
            assert_eq!(byte, 0);
        }
    }

    #[test]
    fn test_hmac_process_key_long() {
        let long_key = [0x42u8; 128]; // 128 bytes, longer than SHA-256 block size
        let processed = Hmac::<Sha256>::process_key(&long_key);
        
        // Should be hash of the key, not the key itself
        let expected_hash = Sha256::compute(&long_key);
        assert_eq!(&processed.as_ref()[..32], expected_hash.as_ref());
        // Rest should be zeros
        for &byte in &processed.as_ref()[32..] {
            assert_eq!(byte, 0);
        }
    }

    #[test]
    fn test_hmac_process_key_exact_block_size() {
        let key = [0x33u8; 64]; // Exactly SHA-256 block size
        let processed = Hmac::<Sha256>::process_key(&key);
        
        // Should copy directly, not hash
        assert_eq!(processed.as_ref(), &key);
    }

    #[test]
    fn test_hmac_update_and_finalize() {
        let key = b"secret_key";
        let message = b"Hello, World!";
        
        let mut hmac = Hmac::<Sha256>::new(key);
        hmac.update(message);
        let result1 = hmac.finalize();
        
        // Test same input produces same output
        let mut hmac2 = Hmac::<Sha256>::new(key);
        hmac2.update(message);
        let result2 = hmac2.finalize();
        
        assert_eq!(result1.as_ref(), result2.as_ref());
    }

    #[test]
    fn test_hmac_incremental_update() {
        let key = b"secret_key";
        let message = b"Hello, World!";
        
        // Single update
        let mut hmac1 = Hmac::<Sha256>::new(key);
        hmac1.update(message);
        let result1 = hmac1.finalize();
        
        // Multiple updates
        let mut hmac2 = Hmac::<Sha256>::new(key);
        hmac2.update(b"Hello, ");
        hmac2.update(b"World!");
        let result2 = hmac2.finalize();
        
        assert_eq!(result1.as_ref(), result2.as_ref());
    }

    #[test]
    fn test_hmac_reset() {
        let key = b"secret_key";
        let message1 = b"First message";
        let message2 = b"Second message";
        
        let mut hmac = Hmac::<Sha256>::new(key);
        
        // First computation
        hmac.update(message1);
        let result1 = hmac.finalize();
        
        // Reset and second computation
        let mut hmac2 = Hmac::<Sha256>::new(key);
        hmac2.update(message1);
        hmac2.reset();
        hmac2.update(message2);
        let result2 = hmac2.finalize();
        
        // Should be same as fresh HMAC with message2
        let mut hmac3 = Hmac::<Sha256>::new(key);
        hmac3.update(message2);
        let result3 = hmac3.finalize();
        
        assert_eq!(result2.as_ref(), result3.as_ref());
        assert_ne!(result1.as_ref(), result2.as_ref());
    }

    #[test]
    fn test_hmac_empty_key() {
        let key = b"";
        let message = b"test message";
        
        let mut hmac = Hmac::<Sha256>::new(key);
        hmac.update(message);
        let _result = hmac.finalize();
        
        // Should not panic with empty key
    }

    #[test]
    fn test_hmac_empty_message() {
        let key = b"secret_key";
        let message = b"";
        
        let mut hmac = Hmac::<Sha256>::new(key);
        hmac.update(message);
        let _result = hmac.finalize();
        
        // Should not panic with empty message
    }

    #[test]
    fn test_hmac_different_keys_different_results() {
        let key1 = b"key1";
        let key2 = b"key2";
        let message = b"same message";
        
        let mut hmac1 = Hmac::<Sha256>::new(key1);
        hmac1.update(message);
        let result1 = hmac1.finalize();
        
        let mut hmac2 = Hmac::<Sha256>::new(key2);
        hmac2.update(message);
        let result2 = hmac2.finalize();
        
        assert_ne!(result1.as_ref(), result2.as_ref());
    }

    #[test]
    fn test_hmac_different_hashers() {
        let key = b"secret_key";
        let message = b"test message";
        
        let mut hmac_sha256 = Hmac::<Sha256>::new(key);
        hmac_sha256.update(message);
        let result_sha256 = hmac_sha256.finalize();
        
        let mut hmac_sha512 = Hmac::<Sha512>::new(key);
        hmac_sha512.update(message);
        let result_sha1 = hmac_sha512.finalize();
        
        // Different hash algorithms should produce different output sizes
        assert_ne!(result_sha256.as_ref().len(), result_sha1.as_ref().len());
        assert_eq!(result_sha256.as_ref().len(), 32); // SHA-256
        assert_eq!(result_sha1.as_ref().len(), 64);   // SHA-512
    }

    #[test]
    fn test_hmac_clone() {
        let key = b"secret_key";
        let message = b"test message";
        
        let mut hmac1 = Hmac::<Sha256>::new(key);
        hmac1.update(message);
        
        let hmac2 = hmac1.clone();
        
        let result1 = hmac1.finalize();
        let result2 = hmac2.finalize();
        
        assert_eq!(result1.as_ref(), result2.as_ref());
    }
}