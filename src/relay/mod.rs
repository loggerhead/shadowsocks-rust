use mio::{Handler, Token, EventSet, EventLoop};

use util::RcCell;

pub use self::tcp_relay::TcpRelay;
pub use self::udp_relay::UdpRelay;
pub use self::tcp_processor::TcpProcessor;
pub use self::udp_processor::UdpProcessor;


#[derive(Clone)]
pub enum Relay {
    Tcp(RcCell<TcpRelay>),
    Udp(RcCell<UdpRelay>),
}

impl Handler for Relay {
    type Message = ();
    type Timeout = Token;

    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        let this = self.clone();
        match this {
            Relay::Tcp(r) => {
                r.borrow_mut().ready(event_loop, token, events);
            }
            Relay::Udp(r) => {
                r.borrow_mut().ready(event_loop, token, events);
            }
        }
    }

    fn timeout(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        let this = self.clone();
        match this {
            Relay::Tcp(r) => {
                r.borrow_mut().timeout(event_loop, token);
            }
            Relay::Udp(r) => {
                r.borrow_mut().timeout(event_loop, token);
            }
        }
    }
}

pub trait MyHandler {
    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet);
    fn timeout(&mut self, event_loop: &mut EventLoop<Relay>, token: Token);
}

macro_rules! base_err {
    (ParseAddrFailed) => ( io_err!("parse socket address from string failed") );
    (InitSocketFailed) => ( io_err!("initialize socket failed") );
    (EventError) => ( io_err!("got a event error") );
    (RegisterFailed) => ( io_err!("register to event loop failed") );
    (ReadFailed, $e:expr) => ( io_err!("read data from socket failed ({})", $e) );
    (WriteFailed, $e:expr) => ( io_err!("write data to socket failed ({})", $e) );
    (BindAddrFailed, $addr:expr) => ( io_err!("bind socket to address {} failed", $addr) );
    (AllocTokenFailed) => ( io_err!("alloc token failed") );
    (DnsResolveFailed, $e:expr) => ( io_err!("dns resolve failed ({})", $e) );
}

macro_rules! processor_err {
    (EnableOneTimeAuthFailed) => ( io_err!("enable one time auth failed") );
    (NotOneTimeAuthSession) => ( io_err!("current connection is not a one time auth session") );
    (ConnectFailed, $e:expr) => ( io_err!("connect to server failed ({})", $e) );
    (EncryptFailed) => ( io_err!("encrypt data failed") );
    (DecryptFailed) => ( io_err!("decrypt data failed") );

    ($($arg:tt)*) => ( base_err!($($arg)*) );
}


mod tcp_relay;
mod udp_relay;
mod tcp_processor;
mod udp_processor;
