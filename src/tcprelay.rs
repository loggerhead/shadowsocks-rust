use std::str::FromStr;
use std::net::{SocketAddr, SocketAddrV4};
use std::rc::Rc;
use std::cell::RefCell;
use std::io::{Result, Error, ErrorKind};

use mio::{Token, EventSet};
use mio::tcp::{TcpListener, TcpStream};
use eventloop::{Dispatcher, Processor};


pub struct TCPRelay {
    token: Option<Token>,
    // hostname_to_cb: Dict<String, Vec<Box<Callback>>>,
    dispatcher: Option<Rc<RefCell<Dispatcher>>>,
    listener: TcpListener,
}

impl TCPRelay {
    pub fn new() -> TCPRelay {
        let socket_addr = SocketAddrV4::from_str("127.0.0.1:8488").unwrap();

        TCPRelay {
            token: None,
            dispatcher: None,
            listener: TcpListener::bind(&SocketAddr::V4(socket_addr)).unwrap(),
        }
    }

    pub fn add_to_loop(mut self, dispatcher: Rc<RefCell<Dispatcher>>) -> Result<Rc<RefCell<TCPRelay>>> {
        self.dispatcher = Some(dispatcher.clone());
        let this = Rc::new(RefCell::new(self));
        let mut dispatcher = dispatcher.borrow_mut();
        let token = dispatcher.add_handler(this.clone()).unwrap();
        this.borrow_mut().token = Some(token);

        let listener = &this.borrow().listener;
        dispatcher.register(listener, token, EventSet::readable()).map(|_| this.clone())
    }
}

impl Processor for TCPRelay {
    fn handle_event(&mut self, _token: Token, events: EventSet) {
        if events.is_error() {
            error!("events error happened on TCPRelay");
        } else {
            match self.listener.accept() {
                Ok(Some((conn, _addr))) => {
                    if let Some(ref dispatcher) = self.dispatcher {
                        let handler = TCPRelayHandler::new(conn);
                        if handler.add_to_loop(dispatcher.clone()).is_err() {
                            error!("Cannot add TCP handler to eventloop");
                        }
                    }
                }
                Ok(None) => { }
                Err(e) => {
                    warn!("TCPRelay accept error: {}", e);
                }
            }
        }
    }
}


struct TCPRelayHandler {
    local_token: Option<Token>,
    local_sock: Option<TcpStream>,
    remote_token: Option<Token>,
}

impl TCPRelayHandler {
    fn new(local_sock: TcpStream) -> TCPRelayHandler {
        TCPRelayHandler {
            local_token: None,
            local_sock: Some(local_sock),
            remote_token: None,
        }
    }

    pub fn add_to_loop(mut self, dispatcher: Rc<RefCell<Dispatcher>>) -> Result<Rc<RefCell<TCPRelayHandler>>> {
        let this = Rc::new(RefCell::new(self));
        let mut dispatcher = dispatcher.borrow_mut();
        let token = dispatcher.add_handler(this.clone()).unwrap();
        this.borrow_mut().local_token = Some(token);

        let res = match this.borrow().local_sock {
            Some(ref local_sock) => {
                dispatcher.register(local_sock, token, EventSet::readable()).map(|_| this.clone())
            }
            None => Err(Error::new(ErrorKind::NotConnected, "Local socket is not created")),
        };

        res
    }
}

impl Processor for TCPRelayHandler {
    fn handle_event(&mut self, token: Token, events: EventSet) {
        if events.is_error() {
            error!("events error happened on TCPRelay");
            return;
        }

        if Some(token) == self.local_token {
            if events.is_readable() || events.is_hup() {
            }

            if events.is_writable() {

            }
            /*
            let mut buf = [0u8; 1024];
            let mut recevied = None;

            if let Some(ref sock) = self.sock {
                if let Ok(Some((len, _addr))) = sock.recv_from(&mut buf) {
                    recevied = Some(&buf[..len]);
                } else {
                    warn!("receive error on DNS socket");
                }
            } else {
                error!("DNS socket closed");
            }

            if recevied.is_some() {
                self.handle_data(recevied.unwrap());
            }
            */
        } else if Some(token) == self.remote_token {
        }
    }
}
