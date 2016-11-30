use std::fmt;
use std::net::SocketAddr;

use util::Error;

enum SocketError {
    InitSocketFailed,
    EventError,
    RegisterFailed,
    ReadFailed(Error),
    WriteFailed(Error),
    BindAddrFailed(SocketAddr),
    AllocTokenFailed,
    ConnectionClosed,
    ParseAddrFailed(String),
}

impl fmt::Debug for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SocketError::InitSocketFailed => write!(f, "initialize socket failed"),
            SocketError::EventError => write!(f, "got a event error"),
            SocketError::RegisterFailed => write!(f, "register to event loop failed"),
            SocketError::ReadFailed(ref e) => write!(f, "read data from socket failed ({})", e),
            SocketError::WriteFailed(ref e) => write!(f, "write data to socket failed ({})", e),
            SocketError::BindAddrFailed(ref addr) => {
                write!(f, "bind socket to address {} failed", addr)
            }
            SocketError::AllocTokenFailed => write!(f, "alloc token failed"),
            SocketError::ConnectionClosed => write!(f, "connection closed by the other side"),
            SocketError::ParseAddrFailed(ref addr) => {
                write!(f, "parse socket address {} failed", addr)
            }
        }
    }
}

mod asyncdns;
