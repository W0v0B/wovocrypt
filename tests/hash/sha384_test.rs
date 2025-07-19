use wovocrypt::hash::Hasher;
use wovocrypt::hash::prelude::Sha384;

use crate::common::{HashGoldData, assert_hash_eq};
use crate::common::utils::{stress_test_hasher};

const SHA384_GOLD_DATA: &[HashGoldData] = &[
    HashGoldData {
        message: b"",
        expected: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    },
    HashGoldData {
        message: b"a",
        expected: "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
    },
    HashGoldData {
        message: b"abc",
        expected: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    },
    HashGoldData {
        message: b"message digest",
        expected: "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
    },
    HashGoldData {
        message: b"abcdefghijklmnopqrstuvwxyz",
        expected: "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
    },
    HashGoldData {
        message: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        expected: "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
    },
];

#[test]
fn test_sha512_gold_data() {
    for data in SHA384_GOLD_DATA {
        assert_hash_eq!(Sha384, data.message, data.expected);
    }
}

#[test]
fn test_sha512_million_a() {
    let message = vec![b'a'; 1000000];
    let result = Sha384::compute(&message);
    let expected = "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_sha512_multi_update() {
    let mut hasher = Sha384::default();
    hasher.update(b"a");
    hasher.update(b"b");
    hasher.update(b"c");
    let result = hasher.finalize();
    let expected = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    assert_eq!(hex::encode(result.as_ref()), expected);
}

#[test]
fn test_sha512_multiple_blocks() {
    let message = vec![b'x'; 200];
    let result = Sha384::compute(&message);
    
    let mut hasher = Sha384::default();
    hasher.update(&message[..64]);
    hasher.update(&message[64..128]);
    hasher.update(&message[128..]);
    let result2 = hasher.finalize();
    
    assert_eq!(result.as_ref(), result2.as_ref());
}

#[cfg(feature = "alloc")]
#[test]
fn test_sha512_vec_methods() {
    let result_vec = Sha384::compute(b"abc").as_ref().to_vec();
    let mut hasher = Sha384::default();
    hasher.update(b"abc");
    let finalize_vec = hasher.clone().finalize_vec();
    let reset_vec = hasher.finalize_and_reset_vec();
    
    assert_eq!(result_vec, finalize_vec);
    assert_eq!(result_vec, reset_vec);
}

#[test]
fn test_sha512_stress() {
    stress_test_hasher::<Sha384>(1000);
}