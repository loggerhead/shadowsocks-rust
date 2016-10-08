use std::slice;
use std::rc::Rc;
use std::ops::BitAnd;
use std::str::FromStr;
use std::cell::RefCell;
use std::io::{Read, Write, Result, Error, ErrorKind};

use rand::{thread_rng, Rng};
use mio::tcp::{TcpStream, Shutdown};
use mio::{EventLoop, Token, Timeout, EventSet, PollOpt};

use socks5;
use config::Config;
use encrypt::Encryptor;
use network::pair2socket_addr;
use asyncdns::{Caller, DNSResolver};
use relay::{Relay, Processor, ProcessResult};
use socks5::{parse_header, check_auth_method, CheckAuthResult};

macro_rules! try_process {
    ($process:expr) => (
        match $process {
            ProcessResult::Success => {},
            res => return res,
        }
    );
}

pub struct TCPProcessor {
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
    data_to_write_to_local: Option<Vec<u8>>,
    data_to_write_to_remote: Option<Vec<u8>>,
    client_address: Option<(String, u16)>,
    server_address: Option<(String, u16)>,
    encryptor: Encryptor,
    downstream_status: StreamStatus,
    upstream_status: StreamStatus,
}

impl TCPProcessor {
    pub fn new(conf: Config, local_sock: TcpStream, dns_resolver: Rc<RefCell<DNSResolver>>) -> TCPProcessor {
        let encryptor = Encryptor::new(conf["password"].as_str().unwrap());
        let stage = if cfg!(feature = "is_client") {
            HandleStage::Init
        } else {
            HandleStage::Addr
        };

        let mut client_address = None;
        if let Ok(addr) = local_sock.peer_addr() {
            client_address = Some((format!("{}", addr.ip()), addr.port()));
        };

        let _ = local_sock.set_nodelay(true);

        TCPProcessor {
            conf: conf,
            stage: stage,
            dns_resolver: dns_resolver,
            timeout: None,
            local_token: None,
            local_sock: Some(local_sock),
            remote_token: None,
            remote_sock: None,
            data_to_write_to_local: None,
            data_to_write_to_remote: None,
            client_address: client_address,
            server_address: None,
            encryptor: encryptor,
            local_interest: EventSet::none(),
            remote_interest: EventSet::none(),
            downstream_status: StreamStatus::Init,
            upstream_status: StreamStatus::WaitReading,
        }
    }

    pub fn set_timeout(&mut self, timeout: Timeout) {
        self.timeout = Some(timeout);
    }

    fn sock_desc(&self, is_local_sock: bool) -> &'static str {
        if is_local_sock { "local" } else { "remote" }
    }

    fn get_tokens(&self) -> Vec<Token> {
        let mut tokens = vec![];
        if let Some(local_token) = self.local_token {
            tokens.push(local_token);
        }
        if let Some(remote_token) = self.remote_token {
            tokens.push(remote_token);
        }
        tokens
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
            if self.data_to_write_to_local.is_none() {
                self.data_to_write_to_local = Some(Vec::with_capacity(BUF_SIZE));
            }
            self.data_to_write_to_local.take().unwrap()
        } else {
            if self.data_to_write_to_remote.is_none() {
                self.data_to_write_to_remote = Some(Vec::with_capacity(BUF_SIZE));
            }
            self.data_to_write_to_remote.take().unwrap()
        }
    }

    fn set_buf(&mut self, buf: Vec<u8>, is_local_sock: bool) {
        if is_local_sock {
            self.data_to_write_to_local = Some(buf);
        } else {
            self.data_to_write_to_remote = Some(buf);
        }
    }

    fn is_buf_empty(&mut self, is_local_sock: bool) -> bool {
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

    pub fn reset_timeout(&mut self, event_loop: &mut EventLoop<Relay>) {
        if self.timeout.is_some() {
            let timeout = self.timeout.take().unwrap();
            event_loop.clear_timeout(timeout);
        }
        let delay = self.conf["timeout"].as_integer().unwrap() as u64;
        self.timeout = event_loop.timeout_ms(self.get_id(), delay).ok();
    }

    fn choose_a_server(&self) -> Option<(String, u16)> {
        let servers = self.conf["servers"].as_slice().unwrap();
        let mut rng = thread_rng();
        let server = rng.choose(servers).unwrap().as_str().unwrap();
        let parts: Vec<&str> = server.splitn(2, ':').collect();
        let addr = parts[0].to_string();
        let port = u16::from_str(parts[1]).unwrap();

        Some((addr, port))
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

        let this = processor2str(self);
        match register_result {
            Ok(_) => debug!("{} has registred {} socket with {:?}", this, self.sock_desc(is_local_sock), events),
            Err(ref e) => error!("{} register {} socket with {:?} failed: {}", this, self.sock_desc(is_local_sock), events, e),
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

        let ptr = buf.as_mut_ptr();
        let cap = buf.capacity();
        let buf_slice = unsafe { &mut slice::from_raw_parts_mut(ptr, cap) };

        let this = processor2str(self);
        let need_destroy = match sock.read(buf_slice) {
            Ok(n) => {
                unsafe { buf.set_len(n); }
                n == 0
            }
            Err(e) => {
                error!("{} read data from {} socket failed: {}", this, self.sock_desc(is_local_sock), e);
                true
            }
        };
        self.set_sock(sock, is_local_sock);

        let need_decrypt = (cfg!(feature = "is_client") && !is_local_sock)
                        || (!cfg!(feature = "is_client") && is_local_sock);

        let (data, need_destroy) = if need_decrypt && !buf.is_empty() {
            match self.encryptor.decrypt(&buf) {
                None => {
                    warn!("{} cannot decrypt data, maybe a error client", this);
                    (None, true)
                }
                decrypted => (decrypted, need_destroy || false),
            }
        } else {
            (Some(buf), need_destroy || false)
        };

        if need_destroy {
            (data, ProcessResult::Failed(self.get_tokens()))
        } else {
            (data, ProcessResult::Success)
        }
    }

    fn write_to_sock(&mut self, data: &[u8], is_local_sock: bool) -> (usize, ProcessResult<Vec<Token>>) {
        let mut sock = self.get_sock(is_local_sock);
        let this = processor2str(self);
        let result = match sock.write(data) {
            Ok(n) => {
                debug!("writed {} bytes to {} socket of {}", n, self.sock_desc(is_local_sock), this);
                (n, ProcessResult::Success)
            }
            Err(e) => {
                error!("{} write to {} socket error: {}", this, self.sock_desc(is_local_sock), e);
                (0, ProcessResult::Failed(self.get_tokens()))
            }
        };
        self.set_sock(sock, is_local_sock);

        result
    }

    // data => remote_sock => ssserver/server
    fn handle_stage_stream(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        let this = processor2str(self);
        trace!("handle stage stream: {}", this);

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

        if cfg!(feature = "is_client") {
            match self.encryptor.encrypt(data) {
                Some(ref data) => try_write!(data),
                _ => {
                    error!("{} encrypt data failed", this);
                    ProcessResult::Failed(self.get_tokens())
                }
            }
        } else {
            try_write!(data)
        }
    }

    fn handle_stage_connecting(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        let this = processor2str(self);
        trace!("handle stage connecting: {}", this);

        if cfg!(feature = "is_client") {
            match self.encryptor.encrypt(data) {
                Some(ref data) => {
                    self.extend_buf(data, REMOTE);
                    ProcessResult::Success
                }
                _ => {
                    error!("{} encrypt data failed", this);
                    ProcessResult::Failed(self.get_tokens())
                }
            }
        } else {
            self.extend_buf(data, REMOTE);
            ProcessResult::Success
        }
    }

    fn handle_stage_addr(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        let this = processor2str(self);
        trace!("handle stage addr: {}", this);

        let data = if cfg!(feature = "is_client") {
            match data[1] {
                socks5::cmd::UDP_ASSOCIATE => {
                    self.stage = HandleStage::UDPAssoc;
                    unimplemented!();
                }
                socks5::cmd::CONNECT => {
                    &data[3..]
                }
                cmd => {
                    error!("unknown socks command: {}", cmd);
                    return ProcessResult::Failed(self.get_tokens());
                }
            }
        } else {
            data
        };

        // parse socks5 header
        match parse_header(data) {
            Some((_addr_type, remote_address, remote_port, header_length)) => {
                self.update_stream(StreamDirection::Up, StreamStatus::WaitWriting);
                self.stage = HandleStage::DNS;
                // remote_address is ssserver
                if cfg!(feature = "is_client") {
                    let response = &[0x05, 0x00, 0x00, 0x01,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x10, 0x10];
                    match self.write_to_sock(response, LOCAL) {
                        (_, ProcessResult::Success) => {},
                        (_, result) => return result,
                    }
                    self.update_stream(StreamDirection::Down, StreamStatus::WaitReading);

                    match self.encryptor.encrypt(data) {
                        Some(ref data) => self.extend_buf(data, REMOTE),
                        _ => {
                            error!("{} encrypt data failed", this);
                            return ProcessResult::Failed(self.get_tokens());
                        }
                    }
                    self.server_address = self.choose_a_server();
                // remote_address is server
                } else {
                    if data.len() > header_length {
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
                ProcessResult::Failed(self.get_tokens())
            }
        }
    }

    fn handle_stage_init(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        let this = processor2str(self);
        trace!("handle stage init: {}", this);

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
                ProcessResult::Failed(self.get_tokens())
            }
            CheckAuthResult::NoAcceptableMethods => {
                self.write_to_sock(&[0x05, 0xff], LOCAL);
                ProcessResult::Failed(self.get_tokens())
            }
        }
    }

    fn on_local_read(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        match self.receive_data(LOCAL) {
            (Some(data), ProcessResult::Success) => {
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
    fn on_remote_read(&mut self, _event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
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
                // client <= local_sock -- remote_sock <= data
                if cfg!(feature = "is_client") {
                    try_write!(&data)
                // ssclient <= local_sock -- remote_sock <= data
                } else {
                    match self.encryptor.encrypt(&data) {
                        Some(ref data) => try_write!(data),
                        _ => ProcessResult::Failed(self.get_tokens()),
                    }
                }
            }
            (_, result @ ProcessResult::Failed(_)) => result,
            _ => ProcessResult::Success
        }
    }

    fn on_write(&mut self, _event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> ProcessResult<Vec<Token>> {
        if self.is_buf_empty(is_local_sock) {
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
                    // shift unfinished bytes
                    let uncompleted_len = buf.len() - nwrite;
                    for i in 0..uncompleted_len {
                        buf[i] = buf[i + nwrite];
                    }
                    unsafe { buf.set_len(uncompleted_len); }

                    self.update_stream_depend_on(uncompleted_len == 0, is_local_sock);
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
}

impl Caller for TCPProcessor {
    fn get_id(&self) -> Token {
        self.remote_token.unwrap()
    }

    fn handle_dns_resolved(&mut self, event_loop: &mut EventLoop<Relay>,
                           hostname_ip: Option<(String, String)>,
                           errmsg: Option<String>)
                           -> ProcessResult<Vec<Token>> {
        let this = processor2str(self);
        trace!("{} handle_dns_resolved: {:?}", this, hostname_ip);

        if let Some(errmsg) = errmsg {
            error!("{} resolve DNS error: {}", this, errmsg);
            return ProcessResult::Failed(self.get_tokens());
        }

        match hostname_ip {
            Some((_hostname, ip)) => {
                self.stage = HandleStage::Connecting;
                let server_address = self.server_address.take().unwrap();
                let port = server_address.1;
                self.server_address = Some(server_address);

                match self.create_connection(&ip, port) {
                    Ok(sock) => {
                        info!("connected {}-{} to {}:{}", address2str(&self.client_address), this, ip, port);
                        self.remote_sock = Some(sock);
                        self.register(event_loop, REMOTE);
                        self.update_stream(StreamDirection::Up, StreamStatus::WaitBoth);
                        self.update_stream(StreamDirection::Down, StreamStatus::WaitReading);
                        self.reregister(event_loop, LOCAL);
                        ProcessResult::Success
                    }
                    Err(e) => {
                        error!("connected {}-{} to {}:{} failed: {}", address2str(&self.client_address), this, ip, port, e);
                        ProcessResult::Failed(self.get_tokens())
                    }
                }
            }
            _ => ProcessResult::Failed(self.get_tokens()),
        }
    }
}

impl Processor for TCPProcessor {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>,
               token: Token,
               events: EventSet)
               -> ProcessResult<Vec<Token>> {
        let this = processor2str(self);
        trace!("current handle stage of {} is {:?}", this, self.stage);

        if Some(token) == self.local_token {
            if events.is_error() {
                let sock = self.local_sock.take().unwrap();
                error!("events error on local {}: {}", this, sock.take_socket_error().unwrap_err());
                return ProcessResult::Failed(self.get_tokens());
            }
            debug!("got events for local {}: {:?}", this, events);

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
                error!("events error on remote {}: {}", this, sock.take_socket_error().unwrap_err());
                return ProcessResult::Failed(self.get_tokens());
            }
            debug!("got events for remote {}: {:?}", this, events);

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

    fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        let this = processor2str(self);
        trace!("destroy processor {}", this);

        if let Some(ref sock) = self.local_sock {
            if let Err(e) = sock.shutdown(Shutdown::Both) {
                match e.kind() {
                    ErrorKind::NotConnected => { }
                    _ => {
                        error!("shutdown local {} failed: {}", this, e);
                    }
                }
            }
        }

        if let Some(ref sock) = self.remote_sock {
            if let Err(e) = sock.shutdown(Shutdown::Both) {
                match e.kind() {
                    ErrorKind::NotConnected => { }
                    _ => {
                        error!("shutdown remote {} failed: {}", this, e);
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
        self.stage = HandleStage::Destroyed;
    }

    fn is_destroyed(&self) -> bool {
        self.stage == HandleStage::Destroyed
    }
}


fn address2str(address: &Option<(String, u16)>) -> String {
    match *address {
        Some((ref host, port)) => format!("{}:{}", host, port),
        _ => "None".to_string(),
    }
}

fn processor2str(p: &mut TCPProcessor) -> String {
    let local_token = p.local_token.unwrap().as_usize();
    let remote_token = p.remote_token.unwrap().as_usize();
    format!("({}, {})", local_token, remote_token)
}


const BUF_SIZE: usize = 32 * 1024;
const LOCAL: bool = true;
const REMOTE: bool = false;
// for each opening port, we have a TCP Relay
// for each connection, we have a TCP Relay Handler to handle the connection
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
            StreamStatus::WaitReading => {
                self != StreamStatus::WaitWriting
            }
            StreamStatus::WaitWriting => {
                self != StreamStatus::WaitReading
            }
            StreamStatus::WaitBoth => true,
            _ => unreachable!(),
        }
    }
}
