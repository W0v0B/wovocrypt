pub mod utils;

pub struct HashGoldData {
    pub message: &'static [u8],
    pub expected: &'static str,
}

pub struct HmacGoldData {
    pub key: &'static [u8],
    pub message: &'static [u8],
    pub expected: &'static str,
}

#[macro_export]
macro_rules! assert_hash_eq {
    ($hasher:ty, $input:expr, $expected:expr) => {
        let result = <$hasher>::compute($input);
        let result_hex = hex::encode(result.as_ref());
        assert_eq!(result_hex, $expected,
            "Failed!! Hash mismatch for message: {:?}",
            core::str::from_utf8($input).unwrap_or("binary data"));
    };
}
pub use crate::assert_hash_eq;

#[macro_export]
macro_rules! assert_mac_eq {
    ($mac:ty, $key:expr, $message:expr, $expected:expr) => {
        let result = <$mac>::compute($key, $message);
        let result_hex = hex::encode(result.as_ref());
        assert_eq!(result_hex, $expected,
            "\nFailed MAC test!\n  Key:      {:?}\n  Message:  \"{}\"\n  Expected: {}\n  Got:      {}\n",
            $key, core::str::from_utf8($message).unwrap_or("binary data"), $expected, result_hex);
    };
}
pub use crate::assert_mac_eq;