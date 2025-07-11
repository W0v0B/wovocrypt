use wovocrypt::mac::{Mac, prelude::Hmac};
use wovocrypt::hash::prelude::Sha256;

use crate::common::{HmacGoldData, assert_mac_eq};
use crate::common::utils::{stress_test_mac};

const HMAC_SHA256_GOLD_DATA: &[HmacGoldData] = &[
    HmacGoldData {
        key: &[0x0b; 20],
        message: b"Hi There",
        expected: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    },
    HmacGoldData {
        key: b"Jefe",
        message: b"what do ya want for nothing?",
        expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    },
    HmacGoldData {
        key: &[0xaa; 20],
        message: &[0xdd; 50],
        expected: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    },
    HmacGoldData {
        key: &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ],
        message: &[0xcd; 50],
        expected: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    },
    HmacGoldData {
        key: &[0x0c; 20],
        message: b"Test With Truncation",
        expected: "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
    },
    HmacGoldData {
        key: &[0xaa; 80],
        message: b"Test Using Larger Than Block-Size Key - Hash Key First",
        expected: "6953025ed96f0c09f80a96f78e6538dbe2e7b820e3dd970e7ddd39091b32352f",
    },
    HmacGoldData {
        key: &[0xaa; 80],
        message: b"This is a test using a larger than block-size key and a larger than block-size data. The key will be hashed before being used by the HMAC algorithm.",
        expected: "4a14bba7f986c8698cf09bc648b7a6effe224bf62d9c55118ed51f3a720c98d0",
    },
];

#[test]
fn test_hmac_sha256_gold_data() {
    for data in HMAC_SHA256_GOLD_DATA {
        assert_mac_eq!(Hmac<Sha256>, data.key, data.message, data.expected);
    }
}

#[test]
fn test_hmac_sha256_million_a() {
    let key = &[0xaa; 20];
    let message = vec![b'a'; 1000000];
    let result = <Hmac<Sha256>>::compute(key, &message);
    let expected_mac_hex = "4513f77e2a587bf6de43c649b880128672b9fed1ede351576b06e4e03cbc3aef";
    assert_eq!(hex::encode(result.as_ref()), expected_mac_hex);
}

#[test]
fn test_hmac_sha256_multi_update() {
    let key = b"Jefe";
    let mut mac = <Hmac<Sha256>>::new(key);
    mac.update(b"what do ya");
    mac.update(b" want for ");
    mac.update(b"nothing?");
    let result = mac.finalize();
    let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_hmac_sha256_multiple_blocks() {
    let key = &[0x0b; 20];
    let message = vec![b'x'; 200];
    let result = <Hmac<Sha256>>::compute(key, &message);
    
    let mut mac = <Hmac<Sha256>>::new(key);
    mac.update(&message[..64]);
    mac.update(&message[64..128]);
    mac.update(&message[128..]);
    let result2 = mac.finalize();
    
    assert_eq!(result.as_ref(), result2.as_ref());
}

#[cfg(feature = "alloc")]
#[test]
fn test_hmac_sha256_vec_methods() {
    let result_vec = <Hmac<Sha256>>::compute(b"abc", b"abc").as_ref().to_vec();
    let mut mac = <Hmac<Sha256>>::new(b"abc");
    mac.update(b"abc");
    let finalize_vec = mac.clone().finalize_vec();
    let reset_vec = mac.finalize_and_reset_vec();
    
    assert_eq!(result_vec, finalize_vec);
    assert_eq!(result_vec, reset_vec);
}

#[test]
fn test_hmac_sha256_stress() {
    stress_test_mac::<Hmac<Sha256>>(1000);
}