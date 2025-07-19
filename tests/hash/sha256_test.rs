use wovocrypt::hash::Hasher;
use wovocrypt::hash::prelude::Sha256;

use crate::common::{HashGoldData, assert_hash_eq};
use crate::common::utils::{stress_test_hasher};

const SHA256_GOLD_DATA: &[HashGoldData] = &[
    HashGoldData {
        message: b"",
        expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    HashGoldData {
        message: b"a",
        expected: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    },
    HashGoldData {
        message: b"abc",
        expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    HashGoldData {
        message: b"message digest",
        expected: "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
    },
    HashGoldData {
        message: b"abcdefghijklmnopqrstuvwxyz",
        expected: "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
    },
    HashGoldData {
        message: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        expected: "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
    },
];

#[test]
fn test_sha256_gold_data() {
    for data in SHA256_GOLD_DATA {
        assert_hash_eq!(Sha256, data.message, data.expected);
    }
}

#[test]
fn test_sha256_million_a() {
    let message = vec![b'a'; 1000000];
    let result = Sha256::compute(&message);
    let expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_sha256_multi_update() {
    let mut hasher = Sha256::default();
    hasher.update(b"a");
    hasher.update(b"b");
    hasher.update(b"c");
    let result = hasher.finalize();
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_sha256_multiple_blocks() {
    let message = vec![b'x'; 200];
    let result = Sha256::compute(&message);
    
    let mut hasher = Sha256::default();
    hasher.update(&message[..64]);
    hasher.update(&message[64..128]);
    hasher.update(&message[128..]);
    let result2 = hasher.finalize();
    
    assert_eq!(result.as_ref(), result2.as_ref());
}

#[cfg(feature = "alloc")]
#[test]
fn test_sha256_vec_methods() {
    let result_vec = Sha256::compute(b"abc").as_ref().to_vec();
    let mut hasher = Sha256::default();
    hasher.update(b"abc");
    let finalize_vec = hasher.clone().finalize_vec();
    let reset_vec = hasher.finalize_and_reset_vec();
    
    assert_eq!(result_vec, finalize_vec);
    assert_eq!(result_vec, reset_vec);
}

#[test]
fn test_sha256_stress() {
    stress_test_hasher::<Sha256>(1000);
}