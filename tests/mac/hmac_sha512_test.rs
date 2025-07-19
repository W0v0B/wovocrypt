use wovocrypt::mac::Mac;
use wovocrypt::mac::prelude::HmacSha512;

use crate::common::{HmacGoldData, assert_mac_eq};
use crate::common::utils::{stress_test_mac};

const HMAC_SHA512_GOLD_DATA: &[HmacGoldData] = &[
    HmacGoldData {
        key: &[0x0b; 20],
        message: b"Hi There",
        expected: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    },
    HmacGoldData {
        key: b"Jefe",
        message: b"what do ya want for nothing?",
        expected: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    },
    HmacGoldData {
        key: &[0xaa; 20],
        message: &[0xdd; 50],
        expected: "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    },
    HmacGoldData {
        key: &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ],
        message: &[0xcd; 50],
        expected: "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
    },
    HmacGoldData {
        key: &[0x0c; 20],
        message: b"Test With Truncation",
        expected: "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b",
    },
    HmacGoldData {
        key: &[0xaa; 80],
        message: b"Test Using Larger Than Block-Size Key - Hash Key First",
        expected: "132c9ebc32531071f6c4d9e8842291e9403e5940f813170a3ba3a0dd6c055c8b8ca587b24c56c47f3c1f2fb8ee8f9fbc8d92deed0f83426be3e8a2e9056778b3",
    },
    HmacGoldData {
        key: &[0xaa; 80],
        message: b"This is a test using a larger than block-size key and a larger than block-size data. The key will be hashed before being used by the HMAC algorithm.",
        expected: "829aa6e391614745dbfe49081dd111b4fe301330311497823790ec0763abeae6f9156acae46b7ae6501952eb4305483c8180313c7b39cd92d3a2b2e30fdc47e8",
    },
];

#[test]
fn test_hmac_sha512_gold_data() {
    for data in HMAC_SHA512_GOLD_DATA {
        assert_mac_eq!(HmacSha512, data.key, data.message, data.expected);
    }
}

#[test]
fn test_hmac_sha512_million_a() {
    let key = &[0xaa; 20];
    let message = vec![b'a'; 1000000];
    let result = HmacSha512::compute(key, &message);
    let expected_mac_hex = "1be9bb8add5e566b60edc0a366cdc35d15280623e36cf7bbdd3da3459615d083e74c89adbd624cdbb3eb70268a15c65ef8eece9efe80e08474ac95a34bd370b1";
    assert_eq!(hex::encode(result.as_ref()), expected_mac_hex);
}

#[test]
fn test_hmac_sha512_multi_update() {
    let key = b"Jefe";
    let mut mac = HmacSha512::new(key);
    mac.update(b"what do ya");
    mac.update(b" want for ");
    mac.update(b"nothing?");
    let result = mac.finalize();
    let expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_hmac_sha512_multiple_blocks() {
    let key = &[0x0b; 20];
    let message = vec![b'x'; 200];
    let result = HmacSha512::compute(key, &message);
    
    let mut mac = HmacSha512::new(key);
    mac.update(&message[..64]);
    mac.update(&message[64..128]);
    mac.update(&message[128..]);
    let result2 = mac.finalize();
    
    assert_eq!(result.as_ref(), result2.as_ref());
}

#[cfg(feature = "alloc")]
#[test]
fn test_hmac_sha512_vec_methods() {
    let result_vec = HmacSha512::compute(b"abc", b"abc").as_ref().to_vec();
    let mut mac = HmacSha512::new(b"abc");
    mac.update(b"abc");
    let finalize_vec = mac.clone().finalize_vec();
    let reset_vec = mac.finalize_and_reset_vec();
    
    assert_eq!(result_vec, finalize_vec);
    assert_eq!(result_vec, reset_vec);
}

#[test]
fn test_hmac_sha512_stress() {
    stress_test_mac::<HmacSha512>(1000);
}