#[cfg(all(feature = "hmac", feature = "sha224"))]
pub mod hmac_sha224_test;

#[cfg(all(feature = "hmac", feature = "sha256"))]
pub mod hmac_sha256_test;

#[cfg(all(feature = "hmac", feature = "sha384"))]
pub mod hmac_sha384_test;

#[cfg(all(feature = "hmac", feature = "sha512"))]
pub mod hmac_sha512_test;