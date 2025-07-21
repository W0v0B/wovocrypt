#[cfg(any(feature = "aes128", feature = "aes192", feature = "aes256"))]
mod consts;

#[cfg(any(feature = "aes128", feature = "aes192", feature = "aes256"))]
mod internal;

#[cfg(feature = "aes128")]
mod aes128;

#[cfg(feature = "aes192")]
mod aes192;

#[cfg(feature = "aes256")]
mod aes256;

pub mod prelude {
    #[cfg(feature = "aes128")]
    pub use super::aes128::Aes128;
    #[cfg(feature = "aes128")]
    pub use super::aes128::Aes128Key;

    #[cfg(feature = "aes192")]
    pub use super::aes192::Aes192;
    #[cfg(feature = "aes192")]
    pub use super::aes192::Aes192Key;

    #[cfg(feature = "aes256")]
    pub use super::aes256::Aes256;
    #[cfg(feature = "aes256")]
    pub use super::aes256::Aes256Key;
}