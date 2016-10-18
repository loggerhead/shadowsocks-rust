use std::rc::Rc;
use std::cell::RefCell;
use std::str::FromStr;

use rand::{thread_rng, Rng};
use mio::{Handler, Token, EventSet, EventLoop};

use config::Config;

pub use self::tcp_relay::TcpRelay;
pub use self::udp_relay::UdpRelay;
pub use self::tcp_processor::TCPProcessor;
pub use self::udp_processor::UdpProcessor;

#[macro_export]
macro_rules! try_process {
    ($process:expr) => (
        match $process {
            ProcessResult::Success => {},
            res => return res,
        }
    )
}

mod tcp_relay;
mod udp_relay;
mod tcp_processor;
mod udp_processor;

// TODO: cleanup below codes
#[derive(Clone)]
pub enum Relay {
    Tcp(Rc<RefCell<TcpRelay>>),
    Udp(Rc<RefCell<UdpRelay>>),
}

impl Handler for Relay {
    type Message = ();
    type Timeout = Token;

    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        let this = self.clone();
        match this {
            Relay::Tcp(r) => r.borrow_mut().ready(event_loop, token, events),
            Relay::Udp(r) => r.borrow_mut().ready(event_loop, token, events),
        }
    }

    fn timeout(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        let this = self.clone();
        match this {
            Relay::Tcp(r) => r.borrow_mut().timeout(event_loop, token),
            Relay::Udp(r) => r.borrow_mut().timeout(event_loop, token),
        }
    }
}

pub trait MyHandler {
    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet);
    fn timeout(&mut self, event_loop: &mut EventLoop<Relay>, token: Token);
}

#[derive(Debug, PartialEq)]
pub enum ProcessResult<T> {
    Success,
    Failed(T),
}

pub fn choose_a_server(conf: &Config) -> Option<(String, u16)> {
    let servers = conf["servers"].as_slice().unwrap();
    let mut rng = thread_rng();
    let server = rng.choose(servers).unwrap().as_str().unwrap();
    let parts: Vec<&str> = server.splitn(2, ':').collect();
    let addr = parts[0].to_string();
    let port = u16::from_str(parts[1]).unwrap();

    Some((addr, port))
}
