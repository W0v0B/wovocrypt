use super::*;

const KEY_128: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
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
            0x4d, 0xc3, 0x16, 0xca, 0x58, 0x05, 0x92, 0xee, 0x00, 0x01, 0xdf, 0x0b, 0xdb, 0xf4, 0xd3, 0x3a
        ],
    },
];

#[test]
fn aes128_cbc_nopadding_roundtrip() {
    for data in AES128_CBC_NOPADDING_GOLD_DATA {
        let mut out_ciphertext = [0u8; 32];
        let mut encryptor = CbcEncryptor::<Aes128, NoPadding>::new(&KEY_128.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..data.ciphertext.len()]).expect("Encryption finalize failed");

        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 32];
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
        let mut out_ciphertext = [0u8; 48];
        let mut encryptor = CbcEncryptor::<Aes128, Pkcs7>::new(&KEY_128.into(), &IV.into());

        let mut encrypt_written = encryptor.update(data.plaintext, &mut out_ciphertext).expect("Encryption update failed");
        encrypt_written += encryptor.finalize(&mut out_ciphertext[encrypt_written..]).expect("Encryption finalize failed");

        assert_eq!(encrypt_written, data.ciphertext.len());
        assert_eq!(&out_ciphertext[..encrypt_written], data.ciphertext);

        let mut out_plaintext = [0u8; 48];
        let mut decryptor = CbcDecryptor::<Aes128, Pkcs7>::new(&KEY_128.into(), &IV.into());

        let mut decrypt_written = decryptor.update(&out_ciphertext[..encrypt_written], &mut out_plaintext).expect("Decryption update failed");
        decrypt_written += decryptor.finalize(&mut out_plaintext[decrypt_written..data.plaintext.len()]).expect("Decryption finalize failed");

        assert_eq!(decrypt_written, data.plaintext.len());
        assert_eq!(&out_plaintext[..decrypt_written], data.plaintext);
    }
}