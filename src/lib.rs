#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;
pub use error::Error;

pub mod hash;
pub use hash::Hasher;
