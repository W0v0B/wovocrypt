use wovocrypt::mac::{Mac, prelude::HmacSha384};

use crate::common::{HmacGoldData, assert_mac_eq};
use crate::common::utils::{stress_test_mac};

const HMAC_SHA384_GOLD_DATA: &[HmacGoldData] = &[
    HmacGoldData {
        key: &[0x0b; 20],
        message: b"Hi There",
        expected: "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
    },
    HmacGoldData {
        key: b"Jefe",
        message: b"what do ya want for nothing?",
        expected: "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
    },
    HmacGoldData {
        key: &[0xaa; 20],
        message: &[0xdd; 50],
        expected: "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
    },
    HmacGoldData {
        key: &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ],
        message: &[0xcd; 50],
        expected: "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
    },
    HmacGoldData {
        key: &[0x0c; 20],
        message: b"Test With Truncation",
        expected: "3abf34c3503b2a23a46efc619baef897f4c8e42c934ce55ccbae9740fcbc1af4ca62269e2a37cd88ba926341efe4aeea",
    },
    HmacGoldData {
        key: &[0xaa; 80],
        message: b"Test Using Larger Than Block-Size Key - Hash Key First",
        expected: "69d2e2f55de9f09878f04d23d8670d49cb734825cdb9cd9e72e446171a43540b90e17cf086e6fa3a599382a286c61340",
    },
    HmacGoldData {
        key: &[0xaa; 80],
        message: b"This is a test using a larger than block-size key and a larger than block-size data. The key will be hashed before being used by the HMAC algorithm.",
        expected: "e93c3ac613cf668da734f557081b77865f3a62dee2e60f6960e24e93667d2bd207e10da425e66d89f0e2df2d449ce3bb",
    },
];

#[test]
fn test_hmac_sha384_gold_data() {
    for data in HMAC_SHA384_GOLD_DATA {
        assert_mac_eq!(HmacSha384, data.key, data.message, data.expected);
    }
}

#[test]
fn test_hmac_sha384_million_a() {
    let key = &[0xaa; 20];
    let message = vec![b'a'; 1000000];
    let result = HmacSha384::compute(key, &message);
    let expected_mac_hex = "181438b2bcf16347c06e2f2654610345a3b29eba2a9bfe0849294f72a907b27f348153f195b0413874293ee5d508fa3d";
    assert_eq!(hex::encode(result.as_ref()), expected_mac_hex);
}

#[test]
fn test_hmac_sha384_multi_update() {
    let key = b"Jefe";
    let mut mac = HmacSha384::new(key);
    mac.update(b"what do ya");
    mac.update(b" want for ");
    mac.update(b"nothing?");
    let result = mac.finalize();
    let expected = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_hmac_sha384_multiple_blocks() {
    let key = &[0x0b; 20];
    let message = vec![b'x'; 200];
    let result = HmacSha384::compute(key, &message);
    
    let mut mac = HmacSha384::new(key);
    mac.update(&message[..64]);
    mac.update(&message[64..128]);
    mac.update(&message[128..]);
    let result2 = mac.finalize();
    
    assert_eq!(result.as_ref(), result2.as_ref());
}

#[cfg(feature = "alloc")]
#[test]
fn test_hmac_sha384_vec_methods() {
    let result_vec = HmacSha384::compute(b"abc", b"abc").as_ref().to_vec();
    let mut mac = HmacSha384::new(b"abc");
    mac.update(b"abc");
    let finalize_vec = mac.clone().finalize_vec();
    let reset_vec = mac.finalize_and_reset_vec();
    
    assert_eq!(result_vec, finalize_vec);
    assert_eq!(result_vec, reset_vec);
}

#[test]
fn test_hmac_sha384_stress() {
    stress_test_mac::<HmacSha384>(1000);
}