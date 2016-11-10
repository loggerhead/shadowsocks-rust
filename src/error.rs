use std::fmt;
use std::result;
use std::convert::From;
use std::net::SocketAddr;

pub use std::io::Error as IoError;
pub use asyncdns::Error as DnsError;
pub use socks5::Error as Socks5Error;
pub use relay::Error as ProcessError;

pub type Result<T> = result::Result<T, Error>;

#[macro_export]
macro_rules! err_from {
    ($e:expr) => { Err(From::from($e)) }
}

pub enum SocketError {
    InitSocketFailed,
    EventError,
    RegisterFailed,
    ReadFailed(IoError),
    WriteFailed(IoError),
    BindAddrFailed(SocketAddr),
    AllocTokenFailed,
    ConnectionClosed,
    ParseAddrFailed(String),
}

impl fmt::Debug for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &SocketError::InitSocketFailed => write!(f, "initialize socket failed"),
            &SocketError::EventError => write!(f, "got a event error"),
            &SocketError::RegisterFailed => write!(f, "register to event loop failed"),
            &SocketError::ReadFailed(ref e) => write!(f, "read data from socket failed ({})", e),
            &SocketError::WriteFailed(ref e) => write!(f, "write data to socket failed ({})", e),
            &SocketError::BindAddrFailed(ref addr) => {
                write!(f, "bind socket to address {} failed", addr)
            }
            &SocketError::AllocTokenFailed => write!(f, "alloc token failed"),
            &SocketError::ConnectionClosed => write!(f, "connection closed by the other side"),
            &SocketError::ParseAddrFailed(ref addr) => {
                write!(f, "parse socket address {} failed", addr)
            }
        }
    }
}

pub enum Error {
    DnsError(DnsError),
    SocketError(SocketError),
    Socks5Error(Socks5Error),
    ProcessError(ProcessError),
    IoError(IoError),
    Other(String),
}

macro_rules! create_from {
    ($err:tt) => (
        impl From<$err> for Error {
            fn from(e: $err) -> Error {
                Error::$err(e)
            }
        }
    )
}

create_from!(DnsError);
create_from!(SocketError);
create_from!(Socks5Error);
create_from!(ProcessError);
create_from!(IoError);

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::DnsError(ref e) => write!(f, "{:?}", e),
            &Error::SocketError(ref e) => write!(f, "{:?}", e),
            &Error::Socks5Error(ref e) => write!(f, "{:?}", e),
            &Error::ProcessError(ref e) => write!(f, "{:?}", e),
            &Error::IoError(ref e) => write!(f, "{:?}", e),
            &Error::Other(ref desc) => write!(f, "{}", desc),
        }
    }
}
