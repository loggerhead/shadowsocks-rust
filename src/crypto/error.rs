use std::io;
use std::fmt;

#[cfg(feature = "openssl")]
use rust_openssl::error::ErrorStack;

use super::Method;

pub type CipherResult<T> = Result<T, Error>;

pub enum Error {
    UnknownMethod(String),
    UnsupportMethod(Method),
    #[cfg(feature = "openssl")]
    OpensslError(ErrorStack),
    IoError(io::Error),
}

#[cfg(feature = "openssl")]
impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Error {
        Error::OpensslError(e)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::UnknownMethod(ref s) => write!(f, "unknown method {}", s),
            &Error::UnsupportMethod(m) => write!(f, "unsupport method {:?}", m),
            #[cfg(feature = "openssl")]
            &Error::OpensslError(ref err) => write!(f, "{:?}", err),
            &Error::IoError(ref err) => write!(f, "{:?}", err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::UnknownMethod(ref s) => write!(f, "unknown method {}", s),
            &Error::UnsupportMethod(m) => write!(f, "unsupport method {:?}", m),
            #[cfg(feature = "openssl")]
            &Error::OpensslError(ref err) => write!(f, "{}", err),
            &Error::IoError(ref err) => write!(f, "{}", err),
        }
    }
}
