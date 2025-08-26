use wovocrypt::cipher::aes::*;
use wovocrypt::cipher::mode::{SymcEncryptor, SymcDecryptor};

pub mod symc_cbc_test;
pub mod symc_ctr_test;

pub struct SymcGoldData {
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
}