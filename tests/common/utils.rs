#[cfg(feature = "std")]
pub fn stress_test_hasher<H: wovocrypt::hash::Hasher>(iterations: usize) {
    let mut hasher = H::default();
    for i in 0..iterations {
        let data = format!("test data {}", i);
        hasher.update(data.as_bytes());
        if i % 100 == 0 {
            let _ = hasher.finalize_and_reset();
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "std")))]
pub fn stress_test_hasher<H: wovocrypt::hash::Hasher>(iterations: usize) {
    extern crate alloc;
    use alloc::format;
    
    let mut hasher = H::default();
    for i in 0..iterations {
        let data = format!("test data {}", i);
        hasher.update(data.as_bytes());
        if i % 100 == 0 {
            let _ = hasher.finalize_and_reset();
        }
    }
}

#[cfg(all(not(feature = "alloc"), not(feature = "std")))]
pub fn stress_test_hasher<H: wovocrypt::hash::Hasher>(iterations: usize) {
    let mut hasher = H::default();
    for i in 0..iterations {
        let data = match i % 4 {
            0 => b"test data 0",
            1 => b"test data 1", 
            2 => b"test data 2",
            _ => b"test data 3",
        };
        hasher.update(data);
        if i % 100 == 0 {
            let _ = hasher.finalize_and_reset();
        }
    }
}