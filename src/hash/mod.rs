use zeroize::Zeroize;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub mod sha256;
pub mod sha224;
pub mod sha512;

pub trait Hasher: Clone + Default + Zeroize {
    const OUTPUT_SIZE: usize;

    type Output: AsRef<[u8]> + AsMut<[u8]> + Clone + Default + Zeroize;

    fn update(&mut self, input: &[u8]);

    fn finalize(self) -> Self::Output where Self: Sized;

    fn reset(&mut self);

    fn output_size(&self) -> usize {
        Self::OUTPUT_SIZE
    }

    fn hash(input: &[u8]) -> Self::Output where Self: Sized {
        let mut hasher = Self::default();
        hasher.update(input);
        hasher.finalize()
    }

    fn finish_and_reset(&mut self) -> Self::Output {
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
    fn finish_and_reset_vec(&mut self) -> Vec<u8> {
        self.finish_and_reset().as_ref().to_vec()
    }
}