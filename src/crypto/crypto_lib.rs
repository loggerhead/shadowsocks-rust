use rust_crypto::aes;
use rust_crypto::rc4::Rc4;
use rust_crypto::hc128::Hc128;
use rust_crypto::salsa20::Salsa20;
use rust_crypto::chacha20::ChaCha20;
use rust_crypto::sosemanuk::Sosemanuk;
use rust_crypto::symmetriccipher::SynchronousStreamCipher;

use super::{Method, Mode};
use super::cipher::StreamCipher;
use super::error::{Error, CipherResult};

pub struct CryptoCipher {
    inner: Box<SynchronousStreamCipher + 'static>,
}

impl CryptoCipher {
    pub fn new(method: Method, _mode: Mode, key: &[u8], iv: &[u8]) -> CipherResult<CryptoCipher> {
        let cipher = match method {
            Method::aes_128_ctr => aes::ctr(aes::KeySize::KeySize128, key, iv),
            Method::aes_192_ctr => aes::ctr(aes::KeySize::KeySize192, key, iv),
            Method::aes_256_ctr => aes::ctr(aes::KeySize::KeySize256, key, iv),
            Method::rc4 => Box::new(Rc4::new(key)),
            Method::hc128 => Box::new(Hc128::new(key, iv)),
            Method::salsa20 => Box::new(Salsa20::new(key, iv)),
            Method::xsalsa20 => Box::new(Salsa20::new_xsalsa20(key, iv)),
            Method::chacha20 => Box::new(ChaCha20::new(key, iv)),
            Method::xchacha20 => Box::new(ChaCha20::new_xchacha20(key, iv)),
            Method::sosemanuk => Box::new(Sosemanuk::new(key, iv)),
            #[cfg(feature = "openssl")]
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
