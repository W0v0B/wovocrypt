use wovocrypt::hash::Hasher;
use wovocrypt::hash::prelude::Sha224;

use crate::common::{HashGoldData, assert_hash_eq};
use crate::common::utils::{stress_test_hasher};

const SHA224_GOLD_DATA: &[HashGoldData] = &[
    HashGoldData {
        message: b"",
        expected: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    },
    HashGoldData {
        message: b"a",
        expected: "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
    },
    HashGoldData {
        message: b"abc",
        expected: "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    },
    HashGoldData {
        message: b"message digest",
        expected: "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
    },
    HashGoldData {
        message: b"abcdefghijklmnopqrstuvwxyz",
        expected: "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
    },
    HashGoldData {
        message: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        expected: "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9",
    },
];

#[test]
fn test_sha224_gold_data() {
    for data in SHA224_GOLD_DATA {
        assert_hash_eq!(Sha224, data.message, data.expected);
    }
}

#[test]
fn test_sha224_million_a() {
    let message = vec![b'a'; 1000000];
    let result = Sha224::compute(&message);
    let expected = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_sha224_multi_update() {
    let mut hasher = Sha224::default();
    hasher.update(b"a");
    hasher.update(b"b");
    hasher.update(b"c");
    let result = hasher.finalize();
    let expected = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_sha224_multiple_blocks() {
    let message = vec![b'x'; 200];
    let result = Sha224::compute(&message);
    
    let mut hasher = Sha224::default();
    hasher.update(&message[..64]);
    hasher.update(&message[64..128]);
    hasher.update(&message[128..]);
    let result2 = hasher.finalize();
    
    assert_eq!(result.as_ref(), result2.as_ref());
}

#[cfg(feature = "alloc")]
#[test]
fn test_sha224_vec_methods() {
    let result_vec = Sha224::compute(b"abc").as_ref().to_vec();
    let mut hasher = Sha224::default();
    hasher.update(b"abc");
    let finalize_vec = hasher.clone().finalize_vec();
    let reset_vec = hasher.finalize_and_reset_vec();
    
    assert_eq!(result_vec, finalize_vec);
    assert_eq!(result_vec, reset_vec);
}

#[test]
fn test_sha224_stress() {
    stress_test_hasher::<Sha224>(1000);
}