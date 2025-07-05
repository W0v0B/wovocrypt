pub mod utils;

pub struct HashGoldData {
    pub message: &'static [u8],
    pub expected: &'static str,
}

#[macro_export]
macro_rules! assert_hash_eq {
    ($hasher:ty, $input:expr, $expected:expr) => {
        let result = <$hasher>::hash($input);
        let result_hex = hex::encode(result.as_ref());
        assert_eq!(result_hex, $expected,
            "Failed!! Hash mismatch for message: {:?}",
            core::str::from_utf8($input).unwrap_or("binary data"));
    };
}