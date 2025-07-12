use wovocrypt::mac::{Mac, prelude::HmacSha224};

use crate::common::{HmacGoldData, assert_mac_eq};
use crate::common::utils::{stress_test_mac};

const HMAC_SHA224_GOLD_DATA: &[HmacGoldData] = &[
    HmacGoldData {
        key: &[0x0b; 20],
        message: b"Hi There",
        expected: "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
    },
    HmacGoldData {
        key: b"Jefe",
        message: b"what do ya want for nothing?",
        expected: "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
    },
    HmacGoldData {
        key: &[0xaa; 20],
        message: &[0xdd; 50],
        expected: "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
    },
    HmacGoldData {
        key: &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ],
        message: &[0xcd; 50],
        expected: "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
    },
    HmacGoldData {
        key: &[0x0c; 20],
        message: b"Test With Truncation",
        expected: "0e2aea68a90c8d37c988bcdb9fca6fa8099cd857c7ec4a1815cac54c",
    },
    HmacGoldData {
        key: &[0xaa; 80],
        message: b"Test Using Larger Than Block-Size Key - Hash Key First",
        expected: "9ed2eebc0ed23576efc815e9b5bc0d9257e36d13e4dd5d5f0c809b38",
    },
    HmacGoldData {
        key: &[0xaa; 80],
        message: b"This is a test using a larger than block-size key and a larger than block-size data. The key will be hashed before being used by the HMAC algorithm.",
        expected: "7487bea58244847a749a669c44bedb90a501d030c7b3d98846c20a95",
    },
];

#[test]
fn test_hmac_sha224_gold_data() {
    for data in HMAC_SHA224_GOLD_DATA {
        assert_mac_eq!(HmacSha224, data.key, data.message, data.expected);
    }
}

#[test]
fn test_hmac_sha224_million_a() {
    let key = &[0xaa; 20];
    let message = vec![b'a'; 1000000];
    let result = HmacSha224::compute(key, &message);
    let expected_mac_hex = "be99840d8fb88c963c5e917fa65903d2c97af7b298a4d7b8679ee7ae";
    assert_eq!(hex::encode(result.as_ref()), expected_mac_hex);
}

#[test]
fn test_hmac_sha224_multi_update() {
    let key = b"Jefe";
    let mut mac = HmacSha224::new(key);
    mac.update(b"what do ya");
    mac.update(b" want for ");
    mac.update(b"nothing?");
    let result = mac.finalize();
    let expected = "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_hmac_sha224_multiple_blocks() {
    let key = &[0x0b; 20];
    let message = vec![b'x'; 200];
    let result = HmacSha224::compute(key, &message);
    
    let mut mac = HmacSha224::new(key);
    mac.update(&message[..64]);
    mac.update(&message[64..128]);
    mac.update(&message[128..]);
    let result2 = mac.finalize();
    
    assert_eq!(result.as_ref(), result2.as_ref());
}

#[cfg(feature = "alloc")]
#[test]
fn test_hmac_sha224_vec_methods() {
    let result_vec = HmacSha224::compute(b"abc", b"abc").as_ref().to_vec();
    let mut mac = HmacSha224::new(b"abc");
    mac.update(b"abc");
    let finalize_vec = mac.clone().finalize_vec();
    let reset_vec = mac.finalize_and_reset_vec();
    
    assert_eq!(result_vec, finalize_vec);
    assert_eq!(result_vec, reset_vec);
}

#[test]
fn test_hmac_sha224_stress() {
    stress_test_mac::<HmacSha224>(1000);
}