use std::str::FromStr;
use std::net::{SocketAddr, SocketAddrV4};
use std::rc::Rc;
use std::cell::RefCell;
use std::io::{Read, Result, Error, ErrorKind};

use mio::{Token, EventSet};
use mio::tcp::{TcpListener, TcpStream};

use eventloop::{Dispatcher, Processor};
use asyncdns::DNSResolver;

const BUF_SIZE: usize = 32 * 1024;

// for each opening port, we have a TCP Relay
// for each connection, we have a TCP Relay Handler to handle the connection
//
// for each handler, we have 2 sockets:
//    local:   connected to the client
//    remote:  connected to remote server

// for each handler, it could be at one of several stages:
enum HandlerStage {
    // only sslocal: auth METHOD received from local, reply with selection message
    Init,
    // addr received from local, query DNS for remote
    Addr,
    // only sslocal: UDP assoc
    UDPAssoc,
    // DNS resolved, connect to remote
    DNS,
    // still connecting, more data from local received
    Connecting,
    // remote connected, piping local and remote
    Stream,
    Destroyed,
}

// for each handler, we have 2 stream directions:
//    upstream:    from client to server direction
//                 read local and write to remote
//    downstream:  from server to client direction
//                 read remote and write to local
enum StreamDirection {
    Up,
    Down,
}

// for each stream, it's waiting for reading, or writing, or both
enum StreamWaitStatus {
    Init,
    Reading,
    Writing,
    ReadWriting,
}


struct TCPRelayHandler {
    stage: HandlerStage,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    is_local: bool,
    local_token: Option<Token>,
    local_sock: Option<TcpStream>,
    remote_token: Option<Token>,
    remote_sock: Option<TcpStream>,
    data_to_write_to_local: Vec<u8>,
    data_to_write_to_remote: Vec<u8>,
}

impl TCPRelayHandler {
    fn new(local_sock: TcpStream, dns_resolver: Rc<RefCell<DNSResolver>>, is_local: bool) -> TCPRelayHandler {
        let stage = if is_local {
            HandlerStage::Init
        } else {
            HandlerStage::Addr
        };

        TCPRelayHandler {
            stage: stage,
            dns_resolver: dns_resolver,
            is_local: true,
            local_token: None,
            local_sock: Some(local_sock),
            remote_token: None,
            remote_sock: None,
            data_to_write_to_local: Vec::new(),
            data_to_write_to_remote: Vec::new(),
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

    fn receive_data(&mut self, is_local_sock: bool) -> Result<Vec<u8>> {
        let sock = if is_local_sock {
            &mut self.local_sock
        } else {
            &mut self.remote_sock
        };

        let mut buf = [0u8; BUF_SIZE];

        match sock {
            &mut Some(ref mut sock) => {
                sock.read(&mut buf).map(|len| buf[..len].to_vec())
            }
            _ => Err(Error::new(ErrorKind::NotConnected, "socket is not initialize")),
        }
    }

    fn write_to_sock(&self, data: &[u8], is_local_sock: bool) {

    }

    fn handle_stage_stream(&self, data: &[u8]) {

    }

    fn handle_stage_connecting(&self, data: &[u8]) {

    }

    fn handle_stage_addr(&self, data: &[u8]) {

    }

    fn handle_stage_init(&mut self, data: &[u8]) {
        match self.check_auth_method(data) {
            // self.write_to_sock(&[0x05, 0xff], true);
            _ => {
            }
        }

        self.write_to_sock(&[0x05, 0x00], true);
        self.stage = HandlerStage::Addr;
    }

    fn check_auth_method(&self, data: &[u8]) {

    }

    fn on_local_read(&mut self) {
        let data = match self.receive_data(true) {
            Ok(data) => {
                if data.len() == 0 {
                    // TODO: destroy
                    return;
                }

                data
            }
            Err(e) => {
                // TODO: handle error
                return;
            }
        };

        match self.stage {
            HandlerStage::Init => {
                self.handle_stage_init(&data);
            }
            HandlerStage::Addr => {
                self.handle_stage_addr(&data);
            }
            HandlerStage::Connecting => {
                self.handle_stage_connecting(&data);
            }
            HandlerStage::Stream => {
                self.handle_stage_stream(&data);
            }
            _ => {

            }
        }
    }

    fn on_local_write(&mut self) {
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
                self.on_local_read();
            }

            if events.is_writable() {
                self.on_local_write();
            }
        } else if Some(token) == self.remote_token {
        }
    }
}


pub struct TCPRelay {
    is_local: bool,
    token: Option<Token>,
    // hostname_to_cb: Dict<String, Vec<Box<Callback>>>,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    dispatcher: Option<Rc<RefCell<Dispatcher>>>,
    listener: TcpListener,
}

impl TCPRelay {
    pub fn new(dns_resolver: Rc<RefCell<DNSResolver>>, is_local: bool) -> TCPRelay {
        let socket_addr = SocketAddrV4::from_str("127.0.0.1:8488").unwrap();

        TCPRelay {
            is_local: is_local,
            token: None,
            dns_resolver: dns_resolver,
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
                        let handler = TCPRelayHandler::new(conn, self.dns_resolver.clone(), self.is_local);
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
