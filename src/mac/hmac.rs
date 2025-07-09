use crate::hash::Hasher;
use crate::mac::Mac;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct Hmac<H: Hasher> {
    inner_hasher: H,
    outer_hasher: H,
}

impl<H: Hasher> Zeroize for Hmac<H> {
    fn zeroize(&mut self) {
        self.inner_hasher.zeroize();
        self.outer_hasher.zeroize();
    }
}
impl<H: Hasher> ZeroizeOnDrop for Hmac<H> {}

impl<H: Hasher> Hmac<H> {
    
}