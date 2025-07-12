use zeroize::Zeroize;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "sha224")]
mod sha224;

#[cfg(feature = "sha256")]
mod sha256;

#[cfg(feature = "sha384")]
mod sha384;

#[cfg(feature = "sha512")]
mod sha512;

pub trait Hasher: Clone + Default + Zeroize {
    const BLOCK_SIZE: usize;
    const OUTPUT_SIZE: usize;
    type HashBlock: AsRef<[u8]> + AsMut<[u8]> + Clone + Default + Zeroize;
    type Output: AsRef<[u8]> + AsMut<[u8]> + Clone + Default + Zeroize;

    fn update(&mut self, input: &[u8]);

    fn finalize(self) -> Self::Output where Self: Sized;

    fn reset(&mut self);

    fn output_size(&self) -> usize {
        Self::OUTPUT_SIZE
    }

    fn compute(input: &[u8]) -> Self::Output where Self: Sized {
        let mut hasher = Self::default();
        hasher.update(input);
        hasher.finalize()
    }

    fn finalize_and_reset(&mut self) -> Self::Output {
        let clone = (*self).clone();
        let result = clone.finalize();
        self.reset();
        result
    }

    #[cfg(feature = "alloc")]
    fn finalize_vec(self) -> Vec<u8> where Self: Sized {
        self.finalize().as_ref().to_vec()
    }

    #[cfg(feature = "alloc")]
    fn finalize_and_reset_vec(&mut self) -> Vec<u8> {
        self.finalize_and_reset().as_ref().to_vec()
    }
}

pub mod prelude {
    pub use super::Hasher;

    #[cfg(feature = "sha224")]
    pub use super::sha224::Sha224;

    #[cfg(feature = "sha256")]
    pub use super::sha256::Sha256;

    #[cfg(feature = "sha384")]
    pub use super::sha384::Sha384;

    #[cfg(feature = "sha512")]
    pub use super::sha512::Sha512;
}