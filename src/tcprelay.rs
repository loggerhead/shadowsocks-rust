use mio::{EventLoop, EventSet, PollOpt, Token, Evented};
use mio::tcp::{TcpListener, TcpStream};
use eventloop;
use eventloop::{Dispatcher, Processor};
use std::net::{SocketAddr, SocketAddrV4};


pub struct TcpRelay {
    // hostname_to_cb: Dict<String, Vec<Box<Callback>>>,
    listener: TcpListener,
    handlers: Vec<TcpRelayHandler>,
}

impl TcpRelay {
    pub fn handle_event(&mut self, event_loop: &mut EventLoop<Dispatcher>, events: EventSet) {
        if events.is_error() {

        } else {
            match self.listener.accept() {
                Ok(Some((conn, _addr))) => {
                    // TcpRelayHandler::new(conn).add_to_loop(event_loop, dispatcher);
                }
                Ok(None) => { }
                Err(e) => {
                    warn!("TcpRelay accept error: {}", e);
                }
            }
        }
    }

    // pub fn add_to_loop(mut self, event_loop: &mut EventLoop<Dispatcher>, dispatcher: &mut Dispatcher) -> Token {
    // }
}


struct TcpRelayHandler {
    local_sock: TcpStream,
}

impl TcpRelayHandler {
    fn new(local_sock: TcpStream) -> TcpRelayHandler {
        TcpRelayHandler {
            local_sock: local_sock,
        }
    }

    pub fn handle_event(&mut self, event_loop: &mut EventLoop<Dispatcher>, events: EventSet) {

    }

    // pub fn add_to_loop(mut self, event_loop: &mut EventLoop<Dispatcher>, dispatcher: &mut Dispatcher) -> Token {
    // }
}