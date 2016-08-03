use std::str::FromStr;
use std::net::{SocketAddr, SocketAddrV4};
use std::rc::Rc;
use std::cell::RefCell;
use std::io::Result;

use mio::{EventSet};
use mio::tcp::{TcpListener, TcpStream};
use eventloop::{Dispatcher, Processor};


pub struct TCPRelay {
    // hostname_to_cb: Dict<String, Vec<Box<Callback>>>,
    dispatcher: Option<Rc<RefCell<Dispatcher>>>,
    listener: TcpListener,
    handlers: Vec<Rc<RefCell<TCPRelayHandler>>>,
}

impl TCPRelay {
    pub fn new() -> TCPRelay {
        let socket_addr = SocketAddrV4::from_str("127.0.0.1:8488").unwrap();

        TCPRelay {
            dispatcher: None,
            listener: TcpListener::bind(&SocketAddr::V4(socket_addr)).unwrap(),
            handlers: vec![],
        }
    }

    pub fn add_to_loop(mut self, dispatcher: Rc<RefCell<Dispatcher>>) -> Result<Rc<RefCell<TCPRelay>>> {
        self.dispatcher = Some(dispatcher.clone());
        let this = Rc::new(RefCell::new(self));
        let mut dispatcher = dispatcher.borrow_mut();
        let token = dispatcher.add_handler(this.clone()).unwrap();
        let listener = &this.borrow().listener;
        dispatcher.register(listener, token, EventSet::readable()).map(|_| this.clone())
    }
}

impl Processor for TCPRelay {
    fn handle_event(&mut self, events: EventSet) {
        if events.is_error() {
            error!("events error happened on TCPRelay");
        } else {
            match self.listener.accept() {
                Ok(Some((conn, _addr))) => {
                    if let Some(ref dispatcher) = self.dispatcher {
                        let mut handler = TCPRelayHandler::new(conn);
                        if let Ok(handler) = handler.add_to_loop(dispatcher.clone()) {
                            self.handlers.push(handler);
                        } else {
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
    local_sock: TcpStream,
}

impl TCPRelayHandler {
    fn new(local_sock: TcpStream) -> TCPRelayHandler {
        TCPRelayHandler {
            local_sock: local_sock,
        }
    }

    pub fn add_to_loop(mut self, dispatcher: Rc<RefCell<Dispatcher>>) -> Result<Rc<RefCell<TCPRelayHandler>>> {
        let this = Rc::new(RefCell::new(self));
        let mut dispatcher = dispatcher.borrow_mut();
        let token = dispatcher.add_handler(this.clone()).unwrap();

        let local_sock = &this.borrow().local_sock;
        dispatcher.register(local_sock, token, EventSet::readable()).map(|_| this.clone())
    }
}

impl Processor for TCPRelayHandler {
    fn handle_event(&mut self, events: EventSet) {
        if events.is_error() {
            error!("events error happened on TCPRelay");
        } else {
        }
    }
}
