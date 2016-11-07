use std::io;
use std::io::Result;
use std::net::SocketAddr;

use mio::{Handler, Token, EventSet, EventLoop};

use mode::ServerChooser;
use config::Config;
use network::pair2addr;
use collections::Holder;
use asyncdns::{DNSResolver, Caller};
use util::{RcCell, new_rc_cell};

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
    (NoServerAvailable) => ( io_err!("no ssserver available") );

    ($($arg:tt)*) => ( base_err!($($arg)*) );
}

fn init_relay<T: MyHandler, P: Caller, F>(conf: Config, f: F) -> Result<T>
    where F: FnOnce(Config,
                    Token,
                    Token,
                    RcCell<DNSResolver>,
                    RcCell<ServerChooser>,
                    Holder<RcCell<P>>,
                    SocketAddr,
                    bool)
                    -> Result<T>
{
    let mut processors = Holder::new();
    let token = try!(processors.alloc_token().ok_or(base_err!(AllocTokenFailed)));
    let dns_token = try!(processors.alloc_token().ok_or(base_err!(AllocTokenFailed)));

    let prefer_ipv6 = conf["prefer_ipv6"].as_bool().unwrap();
    let mut dns_resolver = try!(DNSResolver::new(dns_token, None, prefer_ipv6));
    let server_chooser = try!(ServerChooser::new(&conf));

    let host = conf["listen_address"].as_str().unwrap().to_string();
    let port = conf["listen_port"].as_integer().unwrap() as u16;
    let (_host, ip) = try!(dns_resolver.block_resolve(host)
        .and_then(|h| h.ok_or(base_err!(DnsResolveFailed, "timeout"))));

    let socket_addr = try!(pair2addr(&ip, port).ok_or(base_err!(ParseAddrFailed)));

    f(conf,
      token,
      dns_token,
      new_rc_cell(dns_resolver),
      new_rc_cell(server_chooser),
      processors,
      socket_addr,
      prefer_ipv6)
}

mod tcp_relay;
mod udp_relay;
mod tcp_processor;
mod udp_processor;
