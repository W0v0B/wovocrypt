use super::*;

use wovocrypt::cipher::mode::cbc::{CbcEncryptor, CbcDecryptor};
use wovocrypt::padding::*;

const KEY_128: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const KEY_192: [u8; 24] = [
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
    0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
];
const KEY_256: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];
const IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

const AES128_CBC_NOPADDING_GOLD_DATA: &[SymcGoldData] = &[
    SymcGoldData {
        plaintext: &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ],
        ciphertext: &[
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        ],
    },
    SymcGoldData {
        plaintext: &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        ],
        ciphertext: &[
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
            0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        ],
    },
    
];

const AES128_CBC_PKCS7_GOLD_DATA: &[SymcGoldData] = &[
    SymcGoldData {
        plaintext: b"The quick brown fox jumps over the lazy dog",
        ciphertext: &[
            0xbd, 0x13, 0x20, 0x4f, 0x67, 0xd8, 0x16, 0x7f, 0x20, 0x21, 0x1c, 0x99, 0xb0, 0xa7, 0xcc, 0x05, 
            0x06, 0xd5, 0xc7, 0x03, 0xea, 0xfb, 0x01, 0xa7, 0xd0, 0x47, 0x3b, 0x5c, 0xc9, 0x99, 0xaa, 0xa2,
            0x4d, 0xc3, 0x16, 0xca, 0x58, 0x05, 0x92, 0xee, 0x00, 0x01, 0xdf, 0x0b, 0xdb, 0xf4, 0xd3, 0x3a,
        ],
    },
];

const AES192_CBC_NOPADDING_GOLD_DATA: &[SymcGoldData] = &[
    SymcGoldData {
        plaintext: &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ],
        ciphertext: &[
            0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
        ],
    },
    SymcGoldData {
        plaintext: &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ],
        ciphertext: &[
            0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
            0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
            0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
            0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd,
        ],
    },
];

const AES192_CBC_PKCS7_GOLD_DATA: &[SymcGoldData] = &[
    SymcGoldData {
        plaintext: b"The quick brown fox jumps over the lazy dog",
        ciphertext: &[
            0x8d, 0x41, 0xc8, 0x8a, 0x9a, 0x8f, 0xa6, 0x7d, 0x32, 0x62, 0x13, 0x6b, 0x71, 0xf0, 0x1e, 0x9e,
            0xf9, 0xdf, 0xd9, 0x2f, 0x93, 0xd7, 0x00, 0xbc, 0xe7, 0x6a, 0x32, 0x0b, 0xbe, 0x0c, 0xbe, 0xde,
            0x36, 0x4f, 0xb6, 0x61, 0x69, 0x99, 0x03, 0x26, 0xe2, 0x2d, 0xc8, 0xc3, 0x2d, 0x2c, 0xde, 0x0f,
        ],
    },
];

const AES256_CBC_NOPADDING_GOLD_DATA: &[SymcGoldData] = &[
    SymcGoldData {
        plaintext: &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ],
        ciphertext: &[
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        ],
    },
    SymcGoldData {
        plaintext: &[
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        ],
        ciphertext: &[
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
            0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
        ],
    },
];

const AES256_CBC_PKCS7_GOLD_DATA: &[SymcGoldData] = &[
    SymcGoldData {
        plaintext: b"The quick brown fox jumps over the lazy dog",
        ciphertext: &[
            0x99, 0x3f, 0x48, 0xc8, 0x17, 0x94, 0x6d, 0x0c, 0xcb, 0xa1, 0xd7, 0xc5, 0x38, 0x13, 0xcf, 0x84,
            0x41, 0xe6, 0x13, 0xd2, 0xcb, 0x47, 0x64, 0x5d, 0xc1, 0x82, 0x58, 0x84, 0xad, 0xd9, 0xb9, 0xc9,
            0xb0, 0xb2, 0xa3, 0x59, 0x6e, 0xcd, 0x60, 0x1d, 0xf7, 0x26, 0xbb, 0xaa, 0x5c, 0x08, 0x7b, 0x72,
        ],
    },
];

#[test]
fn aes128_cbc_nopadding_roundtrip() {
    for data in AES128_CBC_NOPADDING_GOLD_DATA {
        let mut out_ciphertext = [0u8; 64];
        let mut encryptor = CbcEncryptor::<Aes128, NoPadding>::new(&KEY_128.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..data.ciphertext.len()]).expect("Encryption finalize failed");

        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 64];
        let mut decryptor = CbcDecryptor::<Aes128, NoPadding>::new(&KEY_128.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}

#[test]
fn aes128_cbc_pkcs7_roundtrip() {
    for data in AES128_CBC_PKCS7_GOLD_DATA {
        let mut out_ciphertext = [0u8; 64];
        let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&KEY_128.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..]).expect("Encryption finalize failed");

        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 64];
        let mut decryptor = CbcDecryptor::<Aes128, Pkcs7>::new(&KEY_128.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}

#[test]
fn aes192_cbc_nopadding_roundtrip() {
    for data in AES192_CBC_NOPADDING_GOLD_DATA {
        let mut out_ciphertext = [0u8; 64];
        let mut encryptor = CbcEncryptor::<Aes192, NoPadding>::new(&KEY_192.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..data.ciphertext.len()]).expect("Encryption finalize failed");

        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 64];
        let mut decryptor = CbcDecryptor::<Aes192, NoPadding>::new(&KEY_192.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}

#[test]
fn aes192_cbc_pkcs7_roundtrip() {
    for data in AES192_CBC_PKCS7_GOLD_DATA {
        let mut out_ciphertext = [0u8; 64];
        let mut encryptor = CbcEncryptor::<Aes192, Pkcs7>::new(&KEY_192.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..]).expect("Encryption finalize failed");

        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 64];
        let mut decryptor = CbcDecryptor::<Aes192, Pkcs7>::new(&KEY_192.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}

#[test]
fn aes256_cbc_nopadding_roundtrip() {
    for data in AES256_CBC_NOPADDING_GOLD_DATA {
        let mut out_ciphertext = [0u8; 64];
        let mut encryptor = CbcEncryptor::<Aes256, NoPadding>::new(&KEY_256.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..data.ciphertext.len()]).expect("Encryption finalize failed");

        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 64];
        let mut decryptor = CbcDecryptor::<Aes256, NoPadding>::new(&KEY_256.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}

#[test]
fn aes256_cbc_pkcs7_roundtrip() {
    for data in AES256_CBC_PKCS7_GOLD_DATA {
        let mut out_ciphertext = [0u8; 64];
        let mut encryptor = CbcEncryptor::<Aes256, Pkcs7>::new(&KEY_256.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..]).expect("Encryption finalize failed");

        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 64];
        let mut decryptor = CbcDecryptor::<Aes256, Pkcs7>::new(&KEY_256.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}

#[test]
fn test_cbc_stress_nopadding() {
    for i in 0..1000 {
        let block = [((i & 0xff) as u8); 16];
        let plaintext = &block[..];

        let mut out_ciphertext = [0u8; 64];
        match i % 3 {
            0 => {
                let mut encryptor = CbcEncryptor::<Aes128, NoPadding>::new(&KEY_128.into(), &IV.into());
                let mut written = encryptor.update(plaintext, &mut out_ciphertext).expect("enc update");
                written += encryptor.finalize(&mut out_ciphertext[written..plaintext.len()]).expect("enc finalize");

                let mut out_plaintext = [0u8; 64];
                let mut decryptor = CbcDecryptor::<Aes128, NoPadding>::new(&KEY_128.into(), &IV.into());
                let mut dwritten = decryptor.update(&out_ciphertext[..written], &mut out_plaintext).expect("dec update");
                dwritten += decryptor.finalize(&mut out_plaintext[dwritten..plaintext.len()]).expect("dec finalize");
                assert_eq!(&out_plaintext[..dwritten], plaintext);
            }
            1 => {
                let mut encryptor = CbcEncryptor::<Aes192, NoPadding>::new(&KEY_192.into(), &IV.into());
                let mut written = encryptor.update(plaintext, &mut out_ciphertext).expect("enc update");
                written += encryptor.finalize(&mut out_ciphertext[written..plaintext.len()]).expect("enc finalize");

                let mut out_plaintext = [0u8; 64];
                let mut decryptor = CbcDecryptor::<Aes192, NoPadding>::new(&KEY_192.into(), &IV.into());
                let mut dwritten = decryptor.update(&out_ciphertext[..written], &mut out_plaintext).expect("dec update");
                dwritten += decryptor.finalize(&mut out_plaintext[dwritten..plaintext.len()]).expect("dec finalize");
                assert_eq!(&out_plaintext[..dwritten], plaintext);
            }
            _ => {
                let mut encryptor = CbcEncryptor::<Aes256, NoPadding>::new(&KEY_256.into(), &IV.into());
                let mut written = encryptor.update(plaintext, &mut out_ciphertext).expect("enc update");
                written += encryptor.finalize(&mut out_ciphertext[written..plaintext.len()]).expect("enc finalize");

                let mut out_plaintext = [0u8; 64];
                let mut decryptor = CbcDecryptor::<Aes256, NoPadding>::new(&KEY_256.into(), &IV.into());
                let mut dwritten = decryptor.update(&out_ciphertext[..written], &mut out_plaintext).expect("dec update");
                dwritten += decryptor.finalize(&mut out_plaintext[dwritten..plaintext.len()]).expect("dec finalize");
                assert_eq!(&out_plaintext[..dwritten], plaintext);
            }
        }
    }
}

#[test]
fn test_cbc_stress_pkcs7() {
    // Stress test PKCS7 padding with variable-length messages and multiple key sizes.
    let samples: &[&[u8]] = &[
        b"a",
        b"hello",
        b"The quick brown fox jumps over the lazy dog",
        b"0123456789abcdef",
        b"0123456789abcdef0123",
    ];

    for i in 0..1000 {
        let msg = samples[i % samples.len()];
        let mut out_ciphertext = [0u8; 256];

        match i % 3 {
            0 => {
                let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&KEY_128.into(), &IV.into());
                let mut written = encryptor.update(msg, &mut out_ciphertext).expect("enc update");
                written += encryptor.finalize(&mut out_ciphertext[written..]).expect("enc finalize");

                let mut out_plaintext = [0u8; 256];
                let mut decryptor = CbcDecryptor::<Aes128, Pkcs7>::new(&KEY_128.into(), &IV.into());
                let mut dwritten = decryptor.update(&out_ciphertext[..written], &mut out_plaintext).expect("dec update");
                dwritten += decryptor.finalize(&mut out_plaintext[dwritten..msg.len()]).expect("dec finalize");
                assert_eq!(&out_plaintext[..dwritten], msg);
            }
            1 => {
                let mut encryptor = CbcEncryptor::<Aes192, Pkcs7>::new(&KEY_192.into(), &IV.into());
                let mut written = encryptor.update(msg, &mut out_ciphertext).expect("enc update");
                written += encryptor.finalize(&mut out_ciphertext[written..]).expect("enc finalize");

                let mut out_plaintext = [0u8; 256];
                let mut decryptor = CbcDecryptor::<Aes192, Pkcs7>::new(&KEY_192.into(), &IV.into());
                let mut dwritten = decryptor.update(&out_ciphertext[..written], &mut out_plaintext).expect("dec update");
                dwritten += decryptor.finalize(&mut out_plaintext[dwritten..msg.len()]).expect("dec finalize");
                assert_eq!(&out_plaintext[..dwritten], msg);
            }
            _ => {
                let mut encryptor = CbcEncryptor::<Aes256, Pkcs7>::new(&KEY_256.into(), &IV.into());
                let mut written = encryptor.update(msg, &mut out_ciphertext).expect("enc update");
                written += encryptor.finalize(&mut out_ciphertext[written..]).expect("enc finalize");

                let mut out_plaintext = [0u8; 256];
                let mut decryptor = CbcDecryptor::<Aes256, Pkcs7>::new(&KEY_256.into(), &IV.into());
                let mut dwritten = decryptor.update(&out_ciphertext[..written], &mut out_plaintext).expect("dec update");
                dwritten += decryptor.finalize(&mut out_plaintext[dwritten..msg.len()]).expect("dec finalize");
                assert_eq!(&out_plaintext[..dwritten], msg);
            }
        }
    }
}