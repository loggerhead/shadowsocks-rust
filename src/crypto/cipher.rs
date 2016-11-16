use std::sync::Arc;

use super::error::CipherResult;
use super::{Method, Mode};
use super::methods::BelongLib;
use super::crypto_lib::CryptoCipher;
#[cfg(feature = "openssl")]
use super::openssl_lib::OpensslCipher;

pub struct Cipher {
    key: Arc<Vec<u8>>,
    iv: Vec<u8>,
    inner: Box<StreamCipher + 'static>,
}

impl Cipher {
    pub fn new(method: Method, mode: Mode, key: Arc<Vec<u8>>, iv: Vec<u8>) -> CipherResult<Cipher> {
        let cipher: Box<StreamCipher> = match method.belong_lib() {
            BelongLib::Crypto => Box::new(CryptoCipher::new(method, mode, &key, &iv)?),
            #[cfg(feature = "openssl")]
            BelongLib::Openssl => Box::new(OpensslCipher::new(method, mode, &key, &iv)?),
        };

        Ok(Cipher {
            key: key,
            iv: iv,
            inner: cipher,
        })
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    pub fn set_iv(&mut self, iv: &[u8]) {
        self.iv[..].copy_from_slice(iv);
    }

    pub fn key_len(&self) -> usize {
        self.key.len()
    }

    pub fn iv_len(&self) -> usize {
        self.iv.len()
    }
}

impl StreamCipher for Cipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CipherResult<()> {
        self.inner.update(input, output)
    }
}

pub trait StreamCipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CipherResult<()>;
}
