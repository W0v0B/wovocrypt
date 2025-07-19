#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;

pub mod hash;

pub mod cipher;

pub mod mac;
