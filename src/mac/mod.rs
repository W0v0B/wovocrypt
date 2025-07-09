use zeroize::Zeroize;
pub mod hmac;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub trait Mac: Clone + Zeroize {
    const OUTPUT_SIZE: usize;

    type Output: AsRef<[u8]> + AsMut<[u8]> + Clone + Default + Zeroize;

    type Key: AsRef<[u8]> + ?Sized;

    fn new(key: &Self::Key) -> Self;

    fn update(&mut self, input: &[u8]);

    fn finalize(self) -> Self::Output where Self: Sized;

    fn reset(&mut self);

    fn output_size(&self) -> usize {
        Self::OUTPUT_SIZE
    }

    fn compute(key: &Self::Key, input: &[u8]) -> Self::Output where Self: Sized {
        let mut mac = Self::new(key);
        mac.update(input);
        mac.finalize()
    }

    fn finalize_and_reset(&mut self) -> Self::Output {
        let clone = self.clone();
        let result = clone.finalize();
        self.reset();
        result
    }

    #[cfg(feature = "alloc")]
    fn finalize_vec(self) -> Vec<u8> where  Self: Sized {
        self.finalize().as_ref().to_vec()
    }

    #[cfg(feature = "alloc")]
    fn finalize_and_reset_vec(&mut self) -> Vec<u8> {
        self.finalize_and_reset().as_ref().to_vec()
    }

    fn verify_mac(expected: &[u8], actual: &Self::Output) -> bool {
        constant_time_eq(expected, actual.as_ref())
    }

    fn verify(key: &Self::Key, input: &[u8], expected_mac: &[u8]) -> bool where Self: Sized {
        let computed_mac = Self::compute(key, input);
        Self::verify_mac(expected_mac, &computed_mac)
    }
}

// Constant time comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}

pub mod prelude {
    pub use super::Mac;

    #[cfg(feature = "hmac")]
    pub use super::hmac::Hmac;
}