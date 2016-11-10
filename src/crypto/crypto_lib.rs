use rust_crypto::aes;
use rust_crypto::symmetriccipher::SynchronousStreamCipher;

use super::{Method, Mode};
use super::error::{Error, CipherResult};
use super::cipher::StreamCipher;

pub struct CryptoCipher {
    inner: Box<SynchronousStreamCipher + 'static>,
}

impl CryptoCipher {
    pub fn new(method: Method, _mode: Mode, key: &[u8], iv: &[u8]) -> CipherResult<CryptoCipher> {
        let cipher = match method {
            Method::aes_256_ctr => aes::ctr(aes::KeySize::KeySize256, key, iv),
            m => return Err(Error::UnsupportMethod(m)),
        };

        Ok(CryptoCipher { inner: cipher })
    }
}

impl StreamCipher for CryptoCipher {
    fn update(&mut self, input: &[u8], output: &mut Vec<u8>) -> CipherResult<()> {
        output.resize(input.len(), 0);
        self.inner.process(input, output);
        Ok(())
    }
}
