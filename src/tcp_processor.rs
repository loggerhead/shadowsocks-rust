use std::rc::Rc;
use std::cell::RefCell;
use std::io::{Read, Write, Result, Error, ErrorKind};

use mio::{EventLoop, Token, EventSet, PollOpt};
use mio::tcp::TcpStream;

use relay::{Relay, Processor};
use common::parse_header;
use network::pair2socket_addr;
use asyncdns::{Caller, DNSResolver};
use encrypt::Encryptor;


const BUF_SIZE: usize = 32 * 1024;
// SOCKS method definition
const METHOD_NOAUTH: u8 = 0;
// SOCKS command definition
const CMD_CONNECT: u8 = 1;
const CMD_BIND: u8 = 2;
const CMD_UDP_ASSOCIATE: u8 = 3;


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
enum HandleStage {
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
    stage: HandleStage,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    is_local: bool,
    local_token: Option<Token>,
    local_sock: Option<TcpStream>,
    remote_token: Option<Token>,
    remote_sock: Option<TcpStream>,
    data_to_write_to_local: Vec<u8>,
    data_to_write_to_remote: Vec<u8>,
    upstream_status: StreamStatus,
    downstream_status: StreamStatus,
    client_address: Option<(String, u16)>,
    server_address: Option<(String, u16)>,
    encryptor: Encryptor,
}

impl TCPProcessor {
    pub fn new(local_sock: TcpStream,
               dns_resolver: Rc<RefCell<DNSResolver>>,
               is_local: bool)
               -> TCPProcessor {
        // TODO: change to configuable
        let password = "test";
        let stage = if is_local {
            HandleStage::Init
        } else {
            HandleStage::Addr
        };

        let mut client_address = None;
        if let Ok(addr) = local_sock.peer_addr() {
            client_address = Some((format!("{}", addr.ip()), addr.port()));
        };

        local_sock.set_nodelay(true).ok();

        TCPProcessor {
            stage: stage,
            dns_resolver: dns_resolver,
            is_local: is_local,
            local_token: None,
            local_sock: Some(local_sock),
            remote_token: None,
            remote_sock: None,
            data_to_write_to_local: Vec::new(),
            data_to_write_to_remote: Vec::new(),
            upstream_status: StreamStatus::Reading,
            downstream_status: StreamStatus::Init,
            client_address: client_address,
            server_address: None,
            encryptor: Encryptor::new(password, is_local),
        }
    }

    pub fn set_remote_token(&mut self, token: Token) {
        self.remote_token = Some(token);
    }

    pub fn add_to_loop(&mut self,
                       token: Token,
                       event_loop: &mut EventLoop<Relay>,
                       events: EventSet,
                       is_local: bool)
                       -> Option<()> {
        let mut sock = if is_local {
            self.local_token = Some(token);
            &mut self.local_sock
        } else {
            self.remote_token = Some(token);
            &mut self.remote_sock
        };

        match sock {
            &mut Some(ref mut sock) => {
                event_loop.register(sock, token, events, PollOpt::level()).ok()
            }
            _ => None,
        }
    }

    fn update_stream(&mut self,
                     event_loop: &mut EventLoop<Relay>,
                     direction: StreamDirection,
                     status: StreamStatus) {
        match direction {
            StreamDirection::Down => {
                if self.downstream_status != status {
                    self.downstream_status = status;
                } else {
                    return;
                }
            }
            StreamDirection::Up => {
                if self.upstream_status != status {
                    self.upstream_status = status;
                } else {
                    return;
                }
            }
        }

        if self.local_sock.is_some() {
            let mut events = EventSet::error() | EventSet::hup();
            match self.downstream_status {
                StreamStatus::Writing |
                StreamStatus::ReadWriting => {
                    events = events | EventSet::writable();
                }
                _ => {}
            }
            match self.upstream_status {
                StreamStatus::Reading |
                StreamStatus::ReadWriting => {
                    events = events | EventSet::readable();
                }
                _ => {}
            }
            let token = self.local_token;
            self.add_to_loop(token.unwrap(), event_loop, events, true);
        }

        if self.remote_sock.is_some() {
            let mut events = EventSet::error() | EventSet::hup();
            match self.downstream_status {
                StreamStatus::Reading |
                StreamStatus::ReadWriting => {
                    events = events | EventSet::readable();
                }
                _ => {}
            }
            match self.upstream_status {
                StreamStatus::Writing |
                StreamStatus::ReadWriting => {
                    events = events | EventSet::writable();
                }
                _ => {}
            }
            let token = self.remote_token;
            self.add_to_loop(token.unwrap(), event_loop, events, false);
        }
    }

    fn receive_data(&mut self, is_local_sock: bool) -> Result<Vec<u8>> {
        let sock = if is_local_sock {
            &mut self.local_sock
        } else {
            &mut self.remote_sock
        };

        let mut buf = [0u8; BUF_SIZE];

        match sock {
            &mut Some(ref mut sock) => sock.read(&mut buf).map(|len| buf[..len].to_vec()),
            _ => Err(Error::new(ErrorKind::NotConnected, "socket is not initialize")),
        }
    }

    fn write_data(&mut self, event_loop: &mut EventLoop<Relay>, is_local_sock: bool) {
        if is_local_sock {
            let data = self.data_to_write_to_local.clone();
            self.write_to_sock(event_loop, &data, true);
            self.data_to_write_to_local.clear();
        } else {
            let data = self.data_to_write_to_remote.clone();
            self.write_to_sock(event_loop, &data, false);
            self.data_to_write_to_remote.clone();
        };
    }

    fn write_to_sock(&mut self,
                     event_loop: &mut EventLoop<Relay>,
                     data: &[u8],
                     is_local_sock: bool) {
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
                _ => (false, true),
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
        // TODO: encrypt
        if !self.is_local {
        }
        self.write_to_sock(event_loop, data, false);
    }

    fn handle_stage_connecting(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) {
        debug!("handle stage connecting");
        self.data_to_write_to_remote.extend_from_slice(data);
    }

    fn handle_stage_addr(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8]) {
        debug!("handle stage addr");
        let data = if self.is_local {
            match data[1] {
                CMD_UDP_ASSOCIATE => {
                    unimplemented!();
                    self.stage = HandleStage::UDPAssoc;
                    return;
                }
                CMD_CONNECT => {
                    &data[3..]
                }
                cmd => {
                    error!("unknown socks command: {}", cmd);
                    self.destroy(event_loop);
                    return;
                }
            }
        } else {
            data
        };

        match parse_header(data) {
            Some((_addr_type, remote_address, remote_port, header_length)) => {
                info!("connecting {}:{}", remote_address, remote_port);
                if self.is_local {
                    let response = &[0x05, 0x00, 0x00, 0x01,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x10, 0x10];
                    self.write_to_sock(event_loop, response, true);

                    self.data_to_write_to_remote.extend_from_slice(data);
                    // TODO: change to configuable
                    self.dns_resolver.borrow_mut().resolve(event_loop, "127.0.0.1".to_string(), self.remote_token.unwrap());
                } else {
                    if data.len() > header_length {
                        self.data_to_write_to_remote.extend_from_slice(&data[header_length..]);
                    }
                    self.dns_resolver.borrow_mut().resolve(event_loop, remote_address.clone(), self.remote_token.unwrap());
                }

                self.server_address = Some((remote_address, remote_port));
                self.update_stream(event_loop, StreamDirection::Up, StreamStatus::Writing);
                self.stage = HandleStage::DNS;
            }
            None => {
                error!("can not parse socks header");
                self.destroy(event_loop);
            }
        }
    }

    fn handle_stage_init(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8]) {
        debug!("handle stage init");
        match self.check_auth_method(data) {
            CheckAuthResult::Success => {
                self.write_to_sock(event_loop, &[0x05, 0x00], true);
                self.stage = HandleStage::Addr;
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
        // TODO: decrypt
        // if !self.is_local {
        //     data = self.encryptor.update(data);
        //     if data.is_none() {
        //         self.destroy(event_loop);
        //     }
        // }

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
            HandleStage::Init => {
                self.handle_stage_init(event_loop, &data);
            }
            HandleStage::Addr => {
                self.handle_stage_addr(event_loop, &data);
            }
            HandleStage::Connecting => {
                self.handle_stage_connecting(event_loop, &data);
            }
            HandleStage::Stream => {
                self.handle_stage_stream(event_loop, &data);
            }
            _ => {}
        }
    }

    fn on_remote_read(&mut self, event_loop: &mut EventLoop<Relay>) {
        // TODO: decrypt
        // if self.is_local {
        //     data = self.encryptor.update(data);
        // }
        match self.receive_data(false) {
            Ok(data) => {
                if data.len() == 0 {
                    self.destroy(event_loop);
                } else {
                    self.write_to_sock(event_loop, &data, true);
                }
            }
            Err(e) => {
                error!("got read data error on remote socket: {}", e);
                self.destroy(event_loop);
            }
        };
    }

    fn on_local_write(&mut self, event_loop: &mut EventLoop<Relay>) {
        // TODO: encrypt
        // if !self.is_local {
        //     data = self.encryptor.update(data);
        // }
        if self.data_to_write_to_local.len() > 0 {
            self.write_data(event_loop, true);
        } else {
            self.update_stream(event_loop, StreamDirection::Down, StreamStatus::Reading);
        }
    }

    fn on_remote_write(&mut self, event_loop: &mut EventLoop<Relay>) {
        // TODO: encrypt
        // if self.is_local {
        //     data = self.encryptor.update(data);
        // }
        self.stage = HandleStage::Stream;
        if self.data_to_write_to_remote.len() > 0 {
            self.write_data(event_loop, false);
        } else {
            self.update_stream(event_loop, StreamDirection::Up, StreamStatus::Reading);
        }
    }

    fn create_connection(&mut self, ip: &str, port: u16) -> Result<TcpStream> {
        match pair2socket_addr(ip, port) {
            Ok(addr) => {
                TcpStream::connect(&addr).map(|sock| {
                    sock.set_nodelay(true).ok();
                    sock
                })
            }
            Err(e) => {
                Err(Error::new(ErrorKind::InvalidData, e))
            }
        }
    }
}

impl Caller for TCPProcessor {
    fn handle_dns_resolved(&mut self, event_loop: &mut EventLoop<Relay>, hostname_ip: Option<(String, String)>, errmsg: Option<&str>) {
        debug!("handle_dns_resolved: {:?}, {:?}", hostname_ip, errmsg);
        if errmsg.is_some() {
            info!("resolve DNS error: {}", errmsg.unwrap());
            self.destroy(event_loop);
            return;
        }

        match hostname_ip {
            Some((_hostname, ip)) => {
                self.stage = HandleStage::Connecting;
                let port = if self.is_local {
                    // TODO: change to configuable
                    8588
                } else {
                    match self.server_address {
                        Some((_, port)) => port,
                        _ => {
                            self.destroy(event_loop);
                            return;
                        }
                    }
                };

                self.remote_sock = match self.create_connection(&ip, port) {
                    Ok(sock) => {
                        let token = self.remote_token;
                        self.add_to_loop(token.unwrap(), event_loop, EventSet::writable() | EventSet::error(), true);
                        self.update_stream(event_loop, StreamDirection::Up, StreamStatus::ReadWriting);
                        self.update_stream(event_loop, StreamDirection::Down, StreamStatus::Reading);

                        Some(sock)
                    }
                    Err(e) => {
                        error!("connect to {} failed: {}", ip, e);
                        self.destroy(event_loop);
                        return;
                    }
                };
            }
            _ => {
                self.destroy(event_loop);
            }
        }
    }
}

impl Processor for TCPProcessor {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        if self.is_destroyed() {
            debug!("ignore process: destroyed");
            return;
        }

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
            if events.is_error() {
                error!("got events error from remote socket on TCPRelay");
                self.destroy(event_loop);
                return;
            }

            if events.is_readable() || events.is_hup() {
                self.on_remote_read(event_loop);
                if self.is_destroyed() {
                    return;
                }
            }

            if events.is_writable() {
                self.on_remote_write(event_loop);
            }
        }
    }

    fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        if self.is_destroyed() {
            debug!("already destroyes");
            return;
        }

        self.stage = HandleStage::Destroyed;

        if self.local_sock.is_some() {
            let sock = self.local_sock.take();
            event_loop.deregister(&sock.unwrap()).ok();
        }

        self.dns_resolver.borrow_mut().remove_caller(self.remote_token.unwrap());
    }

    fn is_destroyed(&self) -> bool {
        self.stage == HandleStage::Destroyed
    }
}
