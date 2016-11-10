use std::convert::From;
#[cfg(feature = "openssl")]
use super::rust_openssl;

mod methods;
mod cipher;
mod encryptor;
pub mod error;

mod crypto_lib;
#[cfg(feature = "openssl")]
mod openssl_lib;

pub use self::methods::Method;
pub use self::cipher::Cipher;
pub use self::encryptor::Encryptor;

#[derive(Debug, Clone, Copy)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

#[cfg(feature = "openssl")]
impl From<Mode> for rust_openssl::symm::Mode {
    fn from(m: Mode) -> rust_openssl::symm::Mode {
        match m {
            Mode::Encrypt => rust_openssl::symm::Mode::Encrypt,
            Mode::Decrypt => rust_openssl::symm::Mode::Decrypt,
        }
    }
}
