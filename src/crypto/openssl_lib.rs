use rust_openssl::symm::{Cipher, Crypter};

use super::{Method, Mode};
use super::error::{Error, CipherResult};
use super::cipher::StreamCipher;

pub struct OpensslCipher {
    block_size: usize,
    inner: Crypter,
}

impl OpensslCipher {
    pub fn new(method: Method, mode: Mode, key: &[u8], iv: &[u8]) -> CipherResult<OpensslCipher> {
        let cipher = match method {
            Method::aes_128_cfb => Cipher::aes_128_cfb128(),
            Method::aes_256_cfb => Cipher::aes_256_cfb128(),
            Method::aes_128_cfb1 => Cipher::aes_128_cfb1(),
            Method::aes_256_cfb1 => Cipher::aes_256_cfb1(),
            Method::aes_128_cfb8 => Cipher::aes_128_cfb8(),
            Method::aes_256_cfb8 => Cipher::aes_256_cfb8(),
            m => return Err(Error::UnsupportMethod(m)),
        };
        let block_size = cipher.block_size();
        let inner = Crypter::new(cipher, mode.into(), key, Some(iv))?;

        Ok(OpensslCipher {
            block_size: block_size,
            inner: inner,
        })
    }
}

impl StreamCipher for OpensslCipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CipherResult<()> {
        let cap = input.len() + self.block_size;
        output.resize(cap, 0);
        let length = self.inner.update(input, output)?;
        output.resize(length, 0);
        Ok(())
    }
}
