use std::rc::Rc;
use std::cell::RefCell;
use std::io::{Read, Write, Result, Error, ErrorKind};

use mio::{EventLoop, Token, EventSet, PollOpt};
use mio::tcp::{TcpStream};

use relay::{Relay, Processor};
use asyncdns::DNSResolver;


const METHOD_NOAUTH: u8 = 0;
const BUF_SIZE: usize = 32 * 1024;


#[derive(PartialEq)]
enum CheckAuthResult {
    Success,
    BadSocksHeader,
    NoAcceptableMethods,
}
// for each opening port, we have a TCP Relay
// for each connection, we have a TCP Relay Handler to handle the connection
//
// for each handler, we have 2 sockets:
//    local:   connected to the client
//    remote:  connected to remote server

// for each handler, it could be at one of several stages:
#[derive(PartialEq)]
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
#[derive(PartialEq)]
enum StreamDirection {
    Up,
    Down,
}

// for each stream, it's waiting for reading, or writing, or both
#[derive(PartialEq)]
enum StreamStatus {
    Init,
    Reading,
    Writing,
    ReadWriting,
}


pub struct TCPProcessor {
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

impl TCPProcessor {
    pub fn new(local_sock: TcpStream, dns_resolver: Rc<RefCell<DNSResolver>>, is_local: bool) -> TCPProcessor {
        let stage = if is_local {
            HandlerStage::Init
        } else {
            HandlerStage::Addr
        };

        TCPProcessor {
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

    pub fn set_remote_token(&mut self, token: Token) {
        self.remote_token = Some(token);
    }

    pub fn add_to_loop(&mut self, token: Token, event_loop: &mut EventLoop<Relay>, is_local: bool) -> Option<()> {
        let mut sock = if is_local {
            self.local_token = Some(token);
            &mut self.local_sock
        } else {
            self.remote_token = Some(token);
            &mut self.remote_sock
        };

        match sock {
            &mut Some(ref mut sock) => {
                event_loop.register(sock,
                                    token,
                                    EventSet::readable(),
                                    PollOpt::level()).ok()
            }
            _ => None
        }
    }

    fn update_stream(&mut self, event_loop: &mut EventLoop<Relay>, direction: StreamDirection, status: StreamStatus) {

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

    fn write_to_sock(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8], is_local_sock: bool) {
        let (need_destroy, uncomplete) = {
            let mut sock;
            let mut data_to_write;
            if is_local_sock {
                sock = &mut self.local_sock;
                data_to_write = &mut self.data_to_write_to_local;
            } else {
                sock = &mut self.remote_sock;
                data_to_write = &mut self.data_to_write_to_remote;
            }

            match sock {
                &mut Some(ref mut sock) => {
                    match sock.write(data) {
                        Ok(size) => {
                            if size == data.len() {
                                (false, false)
                            } else {
                                data_to_write.extend_from_slice(&data[size..]);
                                (false, true)
                            }
                        }
                        Err(e) => {
                            error!("write_to_sock error: {}", e);
                            (true, true)
                        }
                    }
                }
                _ => { (false, true) }
            }
        };

        if need_destroy {
            self.destroy(event_loop);
        } else if uncomplete {
            if is_local_sock {
                self.update_stream(event_loop, StreamDirection::Down, StreamStatus::Writing);
            } else {
                self.update_stream(event_loop, StreamDirection::Up, StreamStatus::Writing);
            }
        } else {
            if is_local_sock {
                self.update_stream(event_loop, StreamDirection::Down, StreamStatus::Reading);
            } else {
                self.update_stream(event_loop, StreamDirection::Up, StreamStatus::Reading);
            }
        }
    }

    fn handle_stage_stream(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8]) {
        debug!("handle stage stream");
    }

    fn handle_stage_connecting(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8]) {
        debug!("handle stage connecting");
    }

    fn handle_stage_addr(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8]) {
        debug!("handle stage addr");
    }

    fn handle_stage_init(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8]) {
        debug!("handle stage init");
        match self.check_auth_method(data) {
            CheckAuthResult::Success => {
                self.write_to_sock(event_loop, &[0x05, 0x00], true);
                self.stage = HandlerStage::Addr;
            }
            CheckAuthResult::BadSocksHeader => {
                self.destroy(event_loop);
            }
            CheckAuthResult::NoAcceptableMethods => {
                self.write_to_sock(event_loop, &[0x05, 0xff], true);
                self.destroy(event_loop);
            }
        }
    }

    fn check_auth_method(&self, data: &[u8]) -> CheckAuthResult {
        if data.len() < 3 {
            warn!("method selection header too short");
            return CheckAuthResult::BadSocksHeader;
        }

        let socks_version = data[0];
        if socks_version != 5 {
            warn!("unsupported SOCKS protocol version {}", socks_version);
            return CheckAuthResult::BadSocksHeader;
        }

        let nmethods = data[1];
        if nmethods < 1 || data.len() as u8 != nmethods + 2 {
            warn!("NMETHODS and number of METHODS mismatch");
            return CheckAuthResult::BadSocksHeader;
        }

        let mut noauto_exist = false;
        for method in &data[2..] {
            if *method == METHOD_NOAUTH {
                noauto_exist = true;
                break;
            }
        }

        if !noauto_exist {
            warn!("none of SOCKS METHOD's requested by client is supported");
            return CheckAuthResult::NoAcceptableMethods;
        }

        return CheckAuthResult::Success;
    }

    fn on_local_read(&mut self, event_loop: &mut EventLoop<Relay>) {
        let data = match self.receive_data(true) {
            Ok(data) => {
                if data.len() == 0 {
                    self.destroy(event_loop);
                    return;
                } else {
                    data
                }
            }
            Err(e) => {
                error!("got read data error on local socket");
                return;
            }
        };

        match self.stage {
            HandlerStage::Init => {
                self.handle_stage_init(event_loop, &data);
            }
            HandlerStage::Addr => {
                self.handle_stage_addr(event_loop, &data);
            }
            HandlerStage::Connecting => {
                self.handle_stage_connecting(event_loop, &data);
            }
            HandlerStage::Stream => {
                self.handle_stage_stream(event_loop, &data);
            }
            _ => {

            }
        }
    }

    fn on_local_write(&mut self, event_loop: &mut EventLoop<Relay>) {
    }

    pub fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        if self.is_destroyed() {
            debug!("already destroyes");
            return;
        }

        self.stage = HandlerStage::Destroyed;

        if self.local_sock.is_some() {
            let sock = self.local_sock.take();
            event_loop.deregister(&sock.unwrap()).ok();
        }
    }
}


impl Processor for TCPProcessor {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        if Some(token) == self.local_token {
            if events.is_error() {
                error!("got events error from local socket on TCPRelay");
                self.destroy(event_loop);
                return;
            }

            if events.is_readable() || events.is_hup() {
                self.on_local_read(event_loop);
                if self.is_destroyed() {
                    return;
                }
            }

            if events.is_writable() {
                self.on_local_write(event_loop);
            }
        } else if Some(token) == self.remote_token {
        }
    }

    fn is_destroyed(&self) -> bool {
        return self.stage == HandlerStage::Destroyed;
    }
}
