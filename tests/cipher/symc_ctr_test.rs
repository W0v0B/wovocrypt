use super::*;

use wovocrypt::cipher::mode::ctr::{CtrEncryptor, CtrDecryptor};

const KEY_128: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];

const KEY_192: [u8; 24] = [
    0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
    0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B,
];

const KEY_256: [u8; 32] = [
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4,
];

const IV: [u8; 12] = [
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
];

const AES128_CTR_GOLD_DATA: &[SymcGoldData] = &[
    SymcGoldData {
        plaintext: &[
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        ],
        ciphertext: &[
            0xe7, 0x09, 0x1b, 0x04, 0x47, 0x9b, 0x56, 0xb8, 0x80, 0x4c, 0xa4, 0xaf, 0x5f, 0x11, 0x88, 0x36
        ],
    },
    SymcGoldData {
        plaintext: &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        ],
        ciphertext: &[
            0x22, 0xe5, 0x2f, 0xb1, 0x77, 0xd8, 0x65, 0xb2, 0xf7, 0xc6, 0xb5, 0x12, 0x69, 0x2d, 0x11, 0x4d,
            0xed, 0x6c, 0x1c, 0x72, 0x25, 0xda, 0xf6, 0xa2, 0xaa, 0xd9, 0xd3, 0xda, 0x2d, 0xba, 0x21, 0x68
        ],
    },
    
];

const AES192_CTR_GOLD_DATA: &[SymcGoldData] = &[
    SymcGoldData {
        plaintext: b"The quick brown fox jumps over the lazy dog",
        ciphertext: &[
            0xF0, 0xEF, 0xB7, 0xE6, 0x3A, 0x57, 0xDE, 0xF9, 0x50, 0x8C, 0x82, 0xFF, 0xFD, 0x50, 0x53, 0xE1,
            0xFC, 0xE6, 0x35, 0x44, 0x3F, 0x24, 0x8D, 0x4C, 0x0C, 0xE6, 0x77, 0x71, 0x5F, 0xF8, 0x4E, 0x88,
            0xB6, 0xFE, 0x57, 0xAD, 0x60, 0xAA, 0x87, 0x8E, 0xEF, 0xD7, 0x6D,
        ],
    },
    SymcGoldData {
        plaintext: b"CTR mode test vector with AES-192 and AES-256!",
        ciphertext: &[
            0xE7, 0xD3, 0x80, 0xE6, 0x26, 0x4D, 0xD3, 0xFF, 0x1B, 0xD8, 0x85, 0xFE, 0xE6, 0x07, 0x4B, 0xA4,
            0xF9, 0xFD, 0x22, 0x16, 0x75, 0x26, 0x89, 0x48, 0x17, 0xE6, 0x59, 0x42, 0x69, 0xA7, 0x5F, 0xC5,
            0xEC, 0xBB, 0x16, 0xAF, 0x65, 0xF0, 0xBF, 0xEB, 0xD8, 0x95, 0x38, 0xFF, 0xF9, 0x95,
        ],
    },
];

const AES256_CTR_GOLD_DATA: &[SymcGoldData] = &[
    SymcGoldData {
        plaintext: b"The quick brown fox jumps over the lazy dog",
        ciphertext: &[
            0xF6, 0x90, 0xA9, 0x81, 0xC1, 0xCA, 0x8F, 0x95, 0xC4, 0x75, 0x35, 0x2F, 0x22, 0xE6, 0x38, 0xC4,
            0x76, 0xD4, 0xBB, 0x41, 0xC1, 0xCD, 0x73, 0x15, 0xA8, 0x2E, 0xC8, 0x9C, 0x12, 0x92, 0xE3, 0x71,
            0xB6, 0x96, 0x3A, 0x05, 0xAF, 0xD0, 0x46, 0x36, 0x6B, 0x2B, 0xBD,
        ],
    },
    SymcGoldData {
        plaintext: b"CTR mode test vector with AES-192 and AES-256!",
        ciphertext: &[
            0xE1, 0xAC, 0x9E, 0x81, 0xDD, 0xD0, 0x82, 0x93, 0x8F, 0x21, 0x32, 0x2E, 0x39, 0xB1, 0x20, 0x81,
            0x73, 0xCF, 0xAC, 0x13, 0x8B, 0xCF, 0x77, 0x11, 0xB3, 0x2E, 0xE6, 0xAF, 0x24, 0xCD, 0xF2, 0x3C,
            0xEC, 0xD3, 0x7B, 0x07, 0xAA, 0x8A, 0x7E, 0x53, 0x5C, 0x69, 0xE8, 0xB0, 0x3E, 0xA4,
        ],
    },
];

#[test]
fn aes128_ctr_roundtrip() {
    for data in AES128_CTR_GOLD_DATA {
        let mut out_ciphertext = [0u8; 64];
        let mut encryptor = CtrEncryptor::<Aes128>::new(&KEY_128.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..data.ciphertext.len()]).expect("Encryption finalize failed");
    
        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 64];
        let mut decryptor = CtrDecryptor::<Aes128>::new(&KEY_128.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}

#[test]
fn aes192_ctr_roundtrip() {
    for data in AES192_CTR_GOLD_DATA {
        let mut out_ciphertext = [0u8; 64];
        let mut encryptor = CtrEncryptor::<Aes192>::new(&KEY_192.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..data.ciphertext.len()]).expect("Encryption finalize failed");
    
        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 64];
        let mut decryptor = CtrDecryptor::<Aes192>::new(&KEY_192.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}

#[test]
fn aes256_ctr_roundtrip() {
    for data in AES256_CTR_GOLD_DATA {
        let mut out_ciphertext = [0u8; 64];
        let mut encryptor = CtrEncryptor::<Aes256>::new(&KEY_256.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..data.ciphertext.len()]).expect("Encryption finalize failed");
    
        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 64];
        let mut decryptor = CtrDecryptor::<Aes256>::new(&KEY_256.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}

#[test]
fn test_cbc_stress() {
    for i in 0..1000 {
        let block = [((i & 0xff) as u8); 16];
        let plaintext = &block[..];

        let mut out_ciphertext = [0u8; 64];
        match i % 3 {
            0 => {
                let mut encryptor = CtrEncryptor::<Aes128>::new(&KEY_128.into(), &IV.into());
                let mut written = encryptor.update(plaintext, &mut out_ciphertext).expect("enc update");
                written += encryptor.finalize(&mut out_ciphertext[written..plaintext.len()]).expect("enc finalize");

                let mut out_plaintext = [0u8; 64];
                let mut decryptor = CtrDecryptor::<Aes128>::new(&KEY_128.into(), &IV.into());
                let mut dwritten = decryptor.update(&out_ciphertext[..written], &mut out_plaintext).expect("dec update");
                dwritten += decryptor.finalize(&mut out_plaintext[dwritten..plaintext.len()]).expect("dec finalize");
                assert_eq!(&out_plaintext[..dwritten], plaintext);
            }
            1 => {
                let mut encryptor = CtrEncryptor::<Aes192>::new(&KEY_192.into(), &IV.into());
                let mut written = encryptor.update(plaintext, &mut out_ciphertext).expect("enc update");
                written += encryptor.finalize(&mut out_ciphertext[written..plaintext.len()]).expect("enc finalize");

                let mut out_plaintext = [0u8; 64];
                let mut decryptor = CtrDecryptor::<Aes192>::new(&KEY_192.into(), &IV.into());
                let mut dwritten = decryptor.update(&out_ciphertext[..written], &mut out_plaintext).expect("dec update");
                dwritten += decryptor.finalize(&mut out_plaintext[dwritten..plaintext.len()]).expect("dec finalize");
                assert_eq!(&out_plaintext[..dwritten], plaintext);
            }
            _ => {
                let mut encryptor = CtrEncryptor::<Aes256>::new(&KEY_256.into(), &IV.into());
                let mut written = encryptor.update(plaintext, &mut out_ciphertext).expect("enc update");
                written += encryptor.finalize(&mut out_ciphertext[written..plaintext.len()]).expect("enc finalize");

                let mut out_plaintext = [0u8; 64];
                let mut decryptor = CtrDecryptor::<Aes256>::new(&KEY_256.into(), &IV.into());
                let mut dwritten = decryptor.update(&out_ciphertext[..written], &mut out_plaintext).expect("dec update");
                dwritten += decryptor.finalize(&mut out_plaintext[dwritten..plaintext.len()]).expect("dec finalize");
                assert_eq!(&out_plaintext[..dwritten], plaintext);
            }
        }
    }
}