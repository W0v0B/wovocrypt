use wovocrypt::hash::Hasher;
use wovocrypt::hash::prelude::Sha512;

use crate::common::{HashGoldData, assert_hash_eq};
use crate::common::utils::{stress_test_hasher};

const SHA512_GOLD_DATA: &[HashGoldData] = &[
    HashGoldData {
        message: b"",
        expected: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    },
    HashGoldData {
        message: b"a",
        expected: "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
    },
    HashGoldData {
        message: b"abc",
        expected: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    },
    HashGoldData {
        message: b"message digest",
        expected: "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
    },
    HashGoldData {
        message: b"abcdefghijklmnopqrstuvwxyz",
        expected: "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
    },
    HashGoldData {
        message: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        expected: "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
    },
];

#[test]
fn test_sha512_gold_data() {
    for data in SHA512_GOLD_DATA {
        assert_hash_eq!(Sha512, data.message, data.expected);
    }
}

#[test]
fn test_sha512_million_a() {
    let message = vec![b'a'; 1000000];
    let result = Sha512::compute(&message);
    let expected = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_sha512_multi_update() {
    let mut hasher = Sha512::default();
    hasher.update(b"a");
    hasher.update(b"b");
    hasher.update(b"c");
    let result = hasher.finalize();
    let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_sha512_multiple_blocks() {
    let message = vec![b'x'; 200];
    let result = Sha512::compute(&message);
    
    let mut hasher = Sha512::default();
    hasher.update(&message[..64]);
    hasher.update(&message[64..128]);
    hasher.update(&message[128..]);
    let result2 = hasher.finalize();
    
    assert_eq!(result.as_ref(), result2.as_ref());
}

#[cfg(feature = "alloc")]
#[test]
fn test_sha512_vec_methods() {
    let result_vec = Sha512::compute(b"abc").as_ref().to_vec();
    let mut hasher = Sha512::default();
    hasher.update(b"abc");
    let finalize_vec = hasher.clone().finalize_vec();
    let reset_vec = hasher.finalize_and_reset_vec();
    
    assert_eq!(result_vec, finalize_vec);
    assert_eq!(result_vec, reset_vec);
}

#[test]
fn test_sha512_stress() {
    stress_test_hasher::<Sha512>(1000);
}