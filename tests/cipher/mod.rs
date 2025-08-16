use wovocrypt::cipher::aes::*;
use wovocrypt::cipher::mode::{SymcEncryptor, SymcDecryptor};
use wovocrypt::cipher::mode::cbc::{CbcEncryptor, CbcDecryptor};
use wovocrypt::padding::*;

pub mod symc_cbc_test;

pub struct SymcGoldData {
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
}