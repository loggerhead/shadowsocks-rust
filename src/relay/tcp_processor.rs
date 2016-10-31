use std::fmt;
use std::rc::Rc;
use std::ops::BitAnd;
use std::cell::RefCell;
use std::borrow::{Cow, Borrow};
use std::io::{Read, Write, Result, Error, ErrorKind};

use mio::tcp::{TcpStream, Shutdown};
use mio::{EventLoop, Token, Timeout, EventSet, PollOpt};

use socks5;
use socks5::addr_type;
use util::shift_vec;
use config::Config;
use encrypt::Encryptor;
use network::{pair2socket_addr, NetworkWriteBytes};
use asyncdns::{Caller, DNSResolver};
use socks5::{pack_addr, parse_header, check_auth_method, CheckAuthResult};
use super::{choose_a_server, Relay, ProcessResult};

pub struct TcpProcessor {
    conf: Config,
    stage: HandleStage,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    timeout: Option<Timeout>,
    local_token: Option<Token>,
    local_sock: Option<TcpStream>,
    remote_token: Option<Token>,
    remote_sock: Option<TcpStream>,
    local_interest: EventSet,
    remote_interest: EventSet,
    local_buf: Option<Vec<u8>>,
    remote_buf: Option<Vec<u8>>,
    client_address: Option<(String, u16)>,
    server_address: Option<(String, u16)>,
    encryptor: Encryptor,
    downstream_status: StreamStatus,
    upstream_status: StreamStatus,
}

impl TcpProcessor {
    pub fn new(conf: Config, local_sock: TcpStream, dns_resolver: Rc<RefCell<DNSResolver>>) -> TcpProcessor {
        let encryptor = Encryptor::new(conf["password"].as_str().unwrap());
        let stage = if cfg!(feature = "sslocal") {
            HandleStage::Init
        } else {
            HandleStage::Addr
        };

        let mut client_address = None;
        if let Ok(addr) = local_sock.peer_addr() {
            client_address = Some((format!("{}", addr.ip()), addr.port()));
        };

        let _ = local_sock.set_nodelay(true);

        TcpProcessor {
            conf: conf,
            stage: stage,
            dns_resolver: dns_resolver,
            timeout: None,
            local_token: None,
            local_sock: Some(local_sock),
            remote_token: None,
            remote_sock: None,
            local_buf: None,
            remote_buf: None,
            client_address: client_address,
            server_address: None,
            encryptor: encryptor,
            local_interest: EventSet::none(),
            remote_interest: EventSet::none(),
            downstream_status: StreamStatus::Init,
            upstream_status: StreamStatus::WaitReading,
        }
    }

    fn sock_desc(&self, is_local_sock: bool) -> &'static str {
        if is_local_sock { "local" } else { "remote" }
    }

    fn get_token(&self, is_local_sock: bool) -> Token {
        if is_local_sock {
            self.local_token.unwrap()
        } else {
            self.remote_token.unwrap()
        }
    }

    pub fn set_token(&mut self, token: Token, is_local_sock: bool) {
        if is_local_sock {
            self.local_token = Some(token);
        } else {
            self.remote_token = Some(token);
        }
    }

    fn get_sock(&mut self, is_local_sock: bool) -> TcpStream {
        if is_local_sock {
            self.local_sock.take().unwrap()
        } else {
            self.remote_sock.take().unwrap()
        }
    }

    pub fn set_sock(&mut self, sock: TcpStream, is_local_sock: bool) {
        if is_local_sock {
            self.local_sock = Some(sock);
        } else {
            self.remote_sock = Some(sock);
        }
    }

    fn get_interest(&self, is_local_sock: bool) -> EventSet {
        if is_local_sock {
            self.local_interest
        } else {
            self.remote_interest
        }
    }

    fn get_buf(&mut self, is_local_sock: bool) -> Vec<u8> {
        if is_local_sock {
            if self.local_buf.is_none() {
                self.local_buf = Some(Vec::with_capacity(BUF_SIZE));
            }
            self.local_buf.take().unwrap()
        } else {
            if self.remote_buf.is_none() {
                self.remote_buf = Some(Vec::with_capacity(BUF_SIZE));
            }
            self.remote_buf.take().unwrap()
        }
    }

    fn set_buf(&mut self, buf: Vec<u8>, is_local_sock: bool) {
        if is_local_sock {
            self.local_buf = Some(buf);
        } else {
            self.remote_buf = Some(buf);
        }
    }

    fn check_buf_empty(&mut self, is_local_sock: bool) -> bool {
        let buf = self.get_buf(is_local_sock);
        let res = buf.is_empty();
        self.set_buf(buf, is_local_sock);
        res
    }

    fn extend_buf(&mut self, data: &[u8], is_local_sock: bool) {
        let mut buf = self.get_buf(is_local_sock);
        buf.extend_from_slice(data);
        self.set_buf(buf, is_local_sock);
    }

    fn process_failed(&self) -> ProcessResult<Vec<Token>> {
        let mut tokens = vec![];
        if let Some(local_token) = self.local_token {
            tokens.push(local_token);
        }
        if let Some(remote_token) = self.remote_token {
            tokens.push(remote_token);
        }
        ProcessResult::Failed(tokens)
    }

    pub fn reset_timeout(&mut self, event_loop: &mut EventLoop<Relay>) {
        if self.timeout.is_some() {
            let timeout = self.timeout.take().unwrap();
            event_loop.clear_timeout(timeout);
        }
        let delay = self.conf["timeout"].as_integer().unwrap() as u64 * 1000;
        self.timeout = event_loop.timeout_ms(self.get_id(), delay).ok();
    }

    fn update_stream(&mut self, stream: StreamDirection, status: StreamStatus) {
        match stream {
            StreamDirection::Down => self.downstream_status = status,
            StreamDirection::Up => self.upstream_status = status,
        }

        if self.local_sock.is_some() {
            self.local_interest = EventSet::none();
            if self.downstream_status & StreamStatus::WaitWriting {
                self.local_interest = self.local_interest | EventSet::writable();
            }
            if self.upstream_status & StreamStatus::WaitReading {
                self.local_interest = self.local_interest | EventSet::readable();
            }
        }

        if self.remote_sock.is_some() {
            self.remote_interest = EventSet::none();
            if self.downstream_status & StreamStatus::WaitReading {
                self.remote_interest = self.remote_interest | EventSet::readable();
            }
            if self.upstream_status & StreamStatus::WaitWriting {
                self.remote_interest = self.remote_interest | EventSet::writable();
            }
        }
    }

    fn update_stream_depend_on(&mut self, is_finished: bool, is_local_sock: bool) {
        let direction = if is_local_sock {
            StreamDirection::Down
        } else {
            StreamDirection::Up
        };
        let status = if is_finished {
            StreamStatus::WaitReading
        } else {
            StreamStatus::WaitWriting
        };

        self.update_stream(direction, status);
    }

    fn do_register(&mut self, event_loop: &mut EventLoop<Relay>, is_local_sock: bool, is_reregister: bool) -> bool {
        let sock = self.get_sock(is_local_sock);
        let token = self.get_token(is_local_sock);
        let events = self.get_interest(is_local_sock);
        let pollopts = PollOpt::edge() | PollOpt::oneshot();

        let register_result = if is_reregister {
            event_loop.reregister(&sock, token, events, pollopts)
        } else {
            event_loop.register(&sock, token, events, pollopts)
        };
        self.set_sock(sock, is_local_sock);

        match register_result {
            Ok(_) => debug!("tcp processor {:?} registered {} socket with {:?}", self, self.sock_desc(is_local_sock), events),
            Err(ref e) => error!("tcp processor {:?} register {} socket with {:?} failed: {}", self, self.sock_desc(is_local_sock), events, e),
        }

        register_result.is_ok()
    }

    pub fn register(&mut self, event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> bool {
        if is_local_sock {
            self.local_interest = EventSet::readable();
        } else {
            self.remote_interest = EventSet::readable() | EventSet::writable();
        }
        self.do_register(event_loop, is_local_sock, REMOTE)
    }

    fn reregister(&mut self, event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> bool {
        self.do_register(event_loop, is_local_sock, LOCAL)
    }

    fn receive_data(&mut self, is_local_sock: bool) -> (Option<Vec<u8>>, ProcessResult<Vec<Token>>) {
        let mut sock = self.get_sock(is_local_sock);
        let mut buf = Vec::with_capacity(BUF_SIZE);
        new_fat_slice_from_vec!(buf_slice, buf);

        let need_destroy = match sock.read(buf_slice) {
            Ok(nread) => {
                unsafe { buf.set_len(nread); }
                nread == 0
            }
            Err(e) => {
                error!("tcp processor {:?} read data from {} socket failed: {}", self, self.sock_desc(is_local_sock), e);
                true
            }
        };
        self.set_sock(sock, is_local_sock);

        let need_decrypt = (cfg!(feature = "sslocal") && !is_local_sock)
                        || (!cfg!(feature = "sslocal") && is_local_sock);

        let (data, need_destroy) = if need_decrypt && !buf.is_empty() {
            if let Some(decrypted) = self.encryptor.decrypt(&buf) {
                (Some(decrypted), need_destroy || false)
            } else {
                warn!("tcp processor {:?} decrypt data failed", self);
                (None, true)
            }
        } else {
            (Some(buf), need_destroy || false)
        };

        if need_destroy {
            (data, self.process_failed())
        } else {
            (data, ProcessResult::Success)
        }
    }

    fn write_to_sock(&mut self, data: &[u8], is_local_sock: bool) -> (usize, ProcessResult<Vec<Token>>) {
        let mut sock = self.get_sock(is_local_sock);
        let result = match sock.write(data) {
            Ok(nwrite) => {
                debug!("written {} bytes to {} socket of {:?}", nwrite, self.sock_desc(is_local_sock), self);
                (nwrite, ProcessResult::Success)
            }
            Err(e) => {
                error!("{:?} write to {} socket error: {}", self, self.sock_desc(is_local_sock), e);
                (0, self.process_failed())
            }
        };
        self.set_sock(sock, is_local_sock);

        result
    }

    // data => remote_sock => ssserver/server
    fn handle_stage_stream(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        trace!("handle stage stream: {:?}", self);

        macro_rules! try_write {
            ($data:expr) => (
                match self.write_to_sock($data, REMOTE) {
                    (nwrite, ProcessResult::Success) => {
                        if nwrite < $data.len() {
                            self.extend_buf(&$data[nwrite..], REMOTE);
                        }
                        self.update_stream_depend_on($data.len() == nwrite, REMOTE);
                        ProcessResult::Success
                    }
                    (_, result) => result,
                }
            )
        }

        if cfg!(feature = "sslocal") {
            match self.encryptor.encrypt(data) {
                Some(ref data) => try_write!(data),
                _ => {
                    error!("{:?} encrypt data failed", self);
                    self.process_failed()
                }
            }
        } else {
            try_write!(data)
        }
    }

    fn handle_stage_connecting(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        trace!("handle stage connecting: {:?}", self);

        if cfg!(feature = "sslocal") {
            match self.encryptor.encrypt(data) {
                Some(ref data) => {
                    self.extend_buf(data, REMOTE);
                    ProcessResult::Success
                }
                _ => {
                    error!("{:?} encrypt data failed", self);
                    self.process_failed()
                }
            }
        } else {
            self.extend_buf(data, REMOTE);
            ProcessResult::Success
        }
    }

    // spec `replies` section of https://www.ietf.org/rfc/rfc1928.txt
    fn handle_stage_addr(&mut self, event_loop: &mut EventLoop<Relay>, mut data: &[u8]) -> ProcessResult<Vec<Token>> {
        trace!("handle stage addr: {:?}", self);

        if cfg!(feature = "sslocal") {
            match data[1] {
                socks5::cmd::UDP_ASSOCIATE => {
                    debug!("UDP associate");
                    self.stage = HandleStage::UDPAssoc;
                    let mut sock = self.local_sock.take().unwrap();
                    match sock.local_addr() {
                        Ok(addr) => {
                            let packed_addr = pack_addr(addr.ip());
                            let mut packed_port = Vec::<u8>::new();
                            let _ = packed_port.put_u16(addr.port());

                            let mut header = Vec::with_capacity(32);
                            // IPv4 header
                            header.extend_from_slice(&[0x05, 0x00, 0x00]);
                            header.extend_from_slice(&packed_addr);
                            header.extend_from_slice(&packed_port);

                            if let Err(e) = sock.write_all(&header) {
                                error!("send UDP associate header failed: {}", e);
                                return self.process_failed();
                            }

                            self.local_sock = Some(sock);
                            return ProcessResult::Success;
                        }
                        Err(e) => {
                            error!("UDP handshake failed: {}", e);
                            return self.process_failed();
                        }
                    }
                }
                socks5::cmd::CONNECT => {
                    data = &data[3..]
                }
                cmd => {
                    error!("unknown socks command: {}", cmd);
                    return self.process_failed();
                }
            }
        }

        // parse socks5 header
        match parse_header(data) {
            Some((addr_type, remote_address, remote_port, header_length)) => {
                let is_ota_enabled = self.conf.get_bool("one_time_auth").unwrap_or(false);
                let is_ota_session = if cfg!(feature = "sslocal") {
                    is_ota_enabled
                } else {
                    addr_type & addr_type::AUTH == addr_type::AUTH
                };
                // if ssserver enabled OTA but client not
                if !cfg!(feature = "sslocal") && is_ota_enabled && !is_ota_session {
                    error!("tcp processor {:?} is not a OTA session", self);
                    return self.process_failed();
                }

                // handle OTA request
                let mut data = Cow::Borrowed(data);
                if is_ota_session {
                    match self.encryptor.enable_ota(addr_type | addr_type::AUTH, header_length, &data) {
                        Some(ota_data) => data = Cow::Owned(ota_data),
                        None => return self.process_failed(),
                    }
                }

                self.update_stream(StreamDirection::Up, StreamStatus::WaitWriting);
                self.stage = HandleStage::DNS;
                // send socks5 response to client
                if cfg!(feature = "sslocal") {
                    let response = &[0x05, 0x00, 0x00, 0x01,
                                     // fake ip
                                     0x00, 0x00, 0x00, 0x00,
                                     // fake port
                                     0x00, 0x00];
                    match self.write_to_sock(response, LOCAL) {
                        (_, ProcessResult::Success) => {},
                        (_, result) => return result,
                    }
                    self.update_stream(StreamDirection::Down, StreamStatus::WaitReading);

                    match self.encryptor.encrypt(data.borrow()) {
                        Some(ref data) => {
                            self.extend_buf(data, REMOTE);
                        }
                        _ => {
                            error!("tcp processor {:?} encrypt data failed", self);
                            return self.process_failed();
                        }
                    }
                    self.server_address = choose_a_server(&self.conf);
                } else {
                    if is_ota_session {
                        self.extend_buf(&data, REMOTE);
                    } else if data.len() > header_length {
                        self.extend_buf(&data[header_length..], REMOTE);
                    }
                    self.server_address = Some((remote_address, remote_port));
                }

                let token = self.get_id();
                let remote_hostname = if let Some(ref server) = self.server_address {
                    server.0.clone()
                } else {
                    unreachable!();
                };

                let resolved = self.dns_resolver.borrow_mut().resolve(token, remote_hostname);
                match resolved {
                    // async resolve hostname
                    (None, None) => ProcessResult::Success,
                    // if hostname is resolved immediately
                    (hostname_ip, errmsg) => self.handle_dns_resolved(event_loop, hostname_ip, errmsg),
                }
            }
            None => {
                error!("can not parse socks header");
                self.process_failed()
            }
        }
    }

    fn handle_stage_init(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        trace!("handle stage init: {:?}", self);

        match check_auth_method(data) {
            CheckAuthResult::Success => {
                match self.write_to_sock(&[0x05, 0x00], LOCAL) {
                    (_, ProcessResult::Success) => {
                        self.stage = HandleStage::Addr;
                        ProcessResult::Success
                    }
                    (_, result) => result,
                }
            }
            CheckAuthResult::BadSocksHeader => {
                self.process_failed()
            }
            CheckAuthResult::NoAcceptableMethods => {
                self.write_to_sock(&[0x05, 0xff], LOCAL);
                self.process_failed()
            }
        }
    }

    fn on_local_read(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        match self.receive_data(LOCAL) {
            (Some(data), ProcessResult::Success) => {
                self.reset_timeout(event_loop);
                match self.stage {
                    HandleStage::Init => {
                        self.handle_stage_init(event_loop, &data)
                    }
                    HandleStage::Addr => {
                        self.handle_stage_addr(event_loop, &data)
                    }
                    HandleStage::Connecting => {
                        self.handle_stage_connecting(event_loop, &data)
                    }
                    HandleStage::Stream => {
                        self.handle_stage_stream(event_loop, &data)
                    }
                    _ => ProcessResult::Success
                }
            }
            (_, result @ ProcessResult::Failed(_)) => result,
            _ => ProcessResult::Success
        }
    }

    // remote_sock <= data
    fn on_remote_read(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        macro_rules! try_write {
            ($data:expr) => (
                match self.write_to_sock($data, LOCAL) {
                    (nwrite, ProcessResult::Success) => {
                        if nwrite < $data.len() {
                            self.extend_buf(&$data[nwrite..], LOCAL);
                        }
                        self.update_stream_depend_on($data.len() == nwrite, LOCAL);

                        ProcessResult::Success
                    }
                    (_, result) => result,
                }
            )
        }

        match self.receive_data(REMOTE) {
            (Some(data), ProcessResult::Success) => {
                self.reset_timeout(event_loop);
                // client <= local_sock -- remote_sock <= data
                if cfg!(feature = "sslocal") {
                    try_write!(&data)
                // ssclient <= local_sock -- remote_sock <= data
                } else {
                    match self.encryptor.encrypt(&data) {
                        Some(ref data) => try_write!(data),
                        _ => self.process_failed(),
                    }
                }
            }
            (_, result @ ProcessResult::Failed(_)) => result,
            _ => ProcessResult::Success
        }
    }

    fn on_write(&mut self, _event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> ProcessResult<Vec<Token>> {
        if self.check_buf_empty(is_local_sock) {
            if is_local_sock {
                self.update_stream(StreamDirection::Down, StreamStatus::WaitReading);
            } else {
                self.update_stream(StreamDirection::Up, StreamStatus::WaitReading);
            }

            ProcessResult::Success
        } else {
            let mut buf = self.get_buf(is_local_sock);
            let result = match self.write_to_sock(&buf, is_local_sock) {
                (nwrite, ProcessResult::Success) => {
                    shift_vec(&mut buf, nwrite);
                    self.update_stream_depend_on(buf.len() == nwrite, is_local_sock);
                    ProcessResult::Success
                }
                (_, result) => result,
            };

            self.set_buf(buf, is_local_sock);

            result
        }
    }

    fn on_local_write(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        self.on_write(event_loop, LOCAL)
    }

    fn on_remote_write(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        self.stage = HandleStage::Stream;
        self.on_write(event_loop, REMOTE)
    }

    fn create_connection(&mut self, ip: &str, port: u16) -> Result<TcpStream> {
        match pair2socket_addr(ip, port) {
            Ok(addr) => {
                TcpStream::connect(&addr).map(|sock| {
                    let _ = sock.set_nodelay(true);
                    sock
                })
            }
            Err(e) => Err(Error::new(ErrorKind::InvalidData, e)),
        }
    }

    pub fn process(&mut self, event_loop: &mut EventLoop<Relay>,
                   token: Token,
                   events: EventSet)
                   -> ProcessResult<Vec<Token>> {
        trace!("current handle stage of {:?} is {:?}", self, self.stage);

        if Some(token) == self.local_token {
            if events.is_error() {
                let sock = self.local_sock.take().unwrap();
                error!("events error on local {:?}: {}", self, sock.take_socket_error().unwrap_err());
                return self.process_failed();
            }
            trace!("got events for local {:?}: {:?}", self, events);

            if events.is_readable() || events.is_hup() {
                try_process!(self.on_local_read(event_loop));
            }

            if events.is_writable() {
                try_process!(self.on_local_write(event_loop));
            }

            self.reregister(event_loop, LOCAL);
        } else if Some(token) == self.remote_token {
            if events.is_error() {
                let sock = self.remote_sock.take().unwrap();
                error!("events error on remote {:?}: {}", self, sock.take_socket_error().unwrap_err());
                return self.process_failed();
            }
            trace!("got events for remote {:?}: {:?}", self, events);

            if events.is_readable() || events.is_hup() {
                try_process!(self.on_remote_read(event_loop));
            }

            if events.is_writable() {
                try_process!(self.on_remote_write(event_loop));
            }

            self.reregister(event_loop, REMOTE);
        }

        ProcessResult::Success
    }

    pub fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        trace!("destroy tcp processor {:?}", self);

        if let Some(ref sock) = self.local_sock {
            if let Err(e) = sock.shutdown(Shutdown::Both) {
                match e.kind() {
                    ErrorKind::NotConnected => { }
                    _ => {
                        error!("shutdown local {:?} failed: {}", self, e);
                    }
                }
            }
        }

        if let Some(ref sock) = self.remote_sock {
            if let Err(e) = sock.shutdown(Shutdown::Both) {
                match e.kind() {
                    ErrorKind::NotConnected => { }
                    _ => {
                        error!("shutdown remote {:?} failed: {}", self, e);
                    }
                }
            }
        }

        if self.timeout.is_some() {
            let timeout = self.timeout.take().unwrap();
            event_loop.clear_timeout(timeout);
        }

        self.dns_resolver.borrow_mut().remove_caller(self.get_id());

        self.local_sock = None;
        self.remote_sock = None;
        self.local_token = None;
        self.remote_token = None;
        self.local_interest = EventSet::none();
        self.remote_interest = EventSet::none();
        self.stage = HandleStage::Destroyed;
    }

    pub fn is_destroyed(&self) -> bool {
        self.stage == HandleStage::Destroyed
    }
}

impl Caller for TcpProcessor {
    fn get_id(&self) -> Token {
        self.remote_token.unwrap()
    }

    fn handle_dns_resolved(&mut self,
                           event_loop: &mut EventLoop<Relay>,
                           hostname_ip: Option<(String, String)>,
                           errmsg: Option<String>)
                           -> ProcessResult<Vec<Token>> {
        trace!("tcp processor {:?} handle_dns_resolved: {:?}", self, hostname_ip);

        if let Some(e) = errmsg {
            error!("tcp processor {:?} got a dns resolve error: {}", self, e);
            return self.process_failed();
        }

        match hostname_ip {
            Some((_hostname, ip)) => {
                self.stage = HandleStage::Connecting;
                let server_address = self.server_address.take().unwrap();
                let port = server_address.1;
                self.server_address = Some(server_address);

                match self.create_connection(&ip, port) {
                    Ok(sock) => {
                        info!("{:?} connected {} to {}:{}", self, address2str(&self.client_address), ip, port);
                        self.remote_sock = Some(sock);
                        self.register(event_loop, REMOTE);
                        self.update_stream(StreamDirection::Up, StreamStatus::WaitBoth);
                        self.update_stream(StreamDirection::Down, StreamStatus::WaitReading);
                        self.reregister(event_loop, LOCAL);
                        ProcessResult::Success
                    }
                    Err(e) => {
                        error!("{:?} connected {} to {}:{} failed: {}", self, address2str(&self.client_address), ip, port, e);
                        self.process_failed()
                    }
                }
            }
            _ => self.process_failed(),
        }
    }
}

impl fmt::Debug for TcpProcessor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let local_token = self.local_token.unwrap().as_usize();
        let remote_token = self.remote_token.unwrap().as_usize();
        write!(f, "({}, {})", local_token, remote_token)
    }
}

fn address2str(address: &Option<(String, u16)>) -> String {
    match *address {
        Some((ref host, port)) => format!("{}:{}", host, port),
        _ => "None".to_string(),
    }
}

const BUF_SIZE: usize = 32 * 1024;
const LOCAL: bool = true;
const REMOTE: bool = false;
// for each opening port, we have a TcpRelay
// for each connection, we have a TcpProcessor to handle the connection
//
// for each handler, we have 2 sockets:
//    local:   connected to the client
//    remote:  connected to remote server

// for each handler, it could be at one of several stages:
#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq)]
enum StreamDirection {
    Down,
    Up
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum StreamStatus {
    Init,
    WaitReading,
    WaitWriting,
    WaitBoth,
}

impl BitAnd for StreamStatus {
    type Output = bool;

    fn bitand(self, rhs: Self) -> Self::Output {
        if self == StreamStatus::Init || rhs == StreamStatus::Init {
            return false;
        }

        match rhs {
            StreamStatus::WaitReading => self != StreamStatus::WaitWriting,
            StreamStatus::WaitWriting => self != StreamStatus::WaitReading,
            StreamStatus::WaitBoth => true,
            _ => unreachable!(),
        }
    }
}
