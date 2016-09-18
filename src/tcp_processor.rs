use std::slice;
use std::rc::Rc;
use std::str::FromStr;
use std::cell::RefCell;
use std::io::{Result, Error, ErrorKind};

use rand::{thread_rng, Rng};
use mio::tcp::{TcpStream, Shutdown};
use mio::prelude::{TryRead, TryWrite};
use mio::{EventLoop, Token, EventSet, PollOpt};

use config::Config;
use util::address2str;
use encrypt::Encryptor;
use common::parse_header;
use network::pair2socket_addr;
use relay::{Relay, Processor, ProcessResult};
use asyncdns::{Caller, DNSResolver};

const BUF_SIZE: usize = 32 * 1024;
// SOCKS method definition
const METHOD_NOAUTH: u8 = 0;
// SOCKS command definition
const CMD_CONNECT: u8 = 1;
const _CMD_BIND: u8 = 2;
const CMD_UDP_ASSOCIATE: u8 = 3;

#[derive(Debug, PartialEq)]
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

pub struct TCPProcessor {
    conf: Config,
    stage: HandleStage,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    local_token: Option<Token>,
    local_sock: Option<TcpStream>,
    remote_token: Option<Token>,
    remote_sock: Option<TcpStream>,
    data_to_write_to_local: Vec<u8>,
    data_to_write_to_remote: Vec<u8>,
    client_address: Option<(String, u16)>,
    server_address: Option<(String, u16)>,
    encryptor: Encryptor,
    interest: EventSet,
}

macro_rules! need_destroy {
    ($this:expr) => (
        {
            let local_token = $this.local_token.unwrap();
            match $this.remote_token {
                Some(remote_token) => ProcessResult::Failed(vec![local_token, remote_token]),
                _ => ProcessResult::Failed(vec![local_token])
            }
        }
    );
}

macro_rules! try_process {
    ($process:expr) => (
        match $process {
            ProcessResult::Success => {},
            res @ _ => return res,
        }
    );
}

macro_rules! processor2str {
    ($this:expr) => (
        {
            let local_token = $this.local_token.clone().unwrap().as_usize();
            let remote_token = $this.remote_token.clone().unwrap().as_usize();
            format!("({}, {})", local_token, remote_token)
        }
    );
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
            local_token: None,
            local_sock: Some(local_sock),
            remote_token: None,
            remote_sock: None,
            data_to_write_to_local: Vec::new(),
            data_to_write_to_remote: Vec::new(),
            client_address: client_address,
            server_address: None,
            encryptor: encryptor,
            interest: EventSet::none(),
        }
    }

    pub fn set_local_token(&mut self, token: Token) {
        self.local_token = Some(token);
    }

    pub fn set_remote_token(&mut self, token: Token) {
        self.remote_token = Some(token);
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

    fn do_register(&mut self, event_loop: &mut EventLoop<Relay>, is_local_sock: bool, is_reregister: bool) -> bool {
        macro_rules! register_sock {
            ($sock:expr, $token:expr) => (
                {
                    let sock = $sock.take().unwrap();
                    let events = self.interest;
                    let pollopts = PollOpt::edge() | PollOpt::oneshot();

                    let register_result = if is_reregister {
                        event_loop.reregister(&sock, $token, events, pollopts)
                    } else {
                        event_loop.register(&sock, $token, events, pollopts)
                    };

                    $sock = Some(sock);

                    match register_result {
                        Ok(_) => {
                            if is_local_sock {
                                debug!("{} has registred local socket with {:?}", processor2str!(self), events);
                            } else {
                                debug!("{} has registred remote socket with {:?}", processor2str!(self), events);
                            }
                            true
                        }
                        Err(e) => {
                            if is_local_sock {
                                error!("{} register local socket with {:?} failed: {}", processor2str!(self), events, e);
                            } else {
                                error!("{} register remote socket with {:?} failed: {}", processor2str!(self), events, e);
                            }
                            false
                        }
                    }
                }
            );
        }

        if is_local_sock {
            register_sock!(self.local_sock, self.local_token.unwrap())
        } else {
            register_sock!(self.remote_sock, self.remote_token.unwrap())
        }
    }

    pub fn register(&mut self, event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> bool {
        self.interest = if is_local_sock {
            EventSet::readable()
        } else {
            EventSet::writable()
        };
        self.do_register(event_loop, is_local_sock, false)
    }

    fn reregister(&mut self, event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> bool {
        self.do_register(event_loop, is_local_sock, true)
    }

    fn change_interest(&mut self, events: EventSet) {
        debug!("{} change to interest to {:?}", processor2str!(self), events);
        self.interest = events;
    }

    fn change_interest_to_rw(&mut self) {
        self.change_interest(EventSet::readable() | EventSet::writable());
    }

    fn change_interest_to_r(&mut self) {
        self.change_interest(EventSet::readable());
    }

    fn receive_data(&mut self, is_local_sock: bool) -> (Option<Vec<u8>>, ProcessResult<Vec<Token>>) {
        let mut sock = if is_local_sock {
            self.local_sock.take().unwrap()
        } else {
            self.remote_sock.take().unwrap()
        };

        let mut buf = Vec::with_capacity(BUF_SIZE);
        let ptr = buf.as_mut_ptr();
        let cap = buf.capacity();
        let buf_slice = unsafe {
            &mut slice::from_raw_parts_mut(ptr, cap)
        };

        let need_destroy = match sock.try_read(buf_slice) {
            Ok(None) => false,
            Ok(Some(0)) => true,
            Ok(Some(n)) => {
                unsafe { buf.set_len(n); }
                false
            }
            Err(e) => {
                if is_local_sock {
                    error!("{} read data from local socket failed: {}", processor2str!(self), e);
                } else {
                    error!("{} read data from remote socket failed: {}", processor2str!(self), e);
                }
                true
            }
        };

        if is_local_sock {
            self.local_sock = Some(sock);
        } else {
            self.remote_sock = Some(sock);
        }

        let need_decrypt = (cfg!(feature = "is_client") && !is_local_sock)
                        || (!cfg!(feature = "is_client") && is_local_sock);

        let (data, need_destroy) = if need_decrypt && buf.len() > 0 {
            match self.encryptor.decrypt(&buf) {
                decrypted @ Some(_) => {
                    (decrypted, need_destroy || false)
                }
                _ => {
                    warn!("{} cannot decrypt data, maybe a error client", processor2str!(self));
                    (None, true)
                }
            }
        } else {
            (Some(buf), need_destroy || false)
        };

        if need_destroy {
            (data, need_destroy!(self))
        } else {
            (data, ProcessResult::Success)
        }
    }

    fn send_buf_data(&mut self, is_local_sock: bool) -> ProcessResult<Vec<Token>> {
        let data;
        if is_local_sock {
            data = self.data_to_write_to_local.clone();
            self.data_to_write_to_local.clear();
        } else {
            data = self.data_to_write_to_remote.clone();
            self.data_to_write_to_remote.clear();
        };

        self.write_to_sock(&data, is_local_sock)
    }

    fn write_to_sock(&mut self, data: &[u8], is_local_sock: bool) -> ProcessResult<Vec<Token>> {
        if data.len() == 0 {
            return ProcessResult::Success;
        }

        let need_encrypt = (cfg!(feature = "is_client") && !is_local_sock)
                        || (!cfg!(feature = "is_client") && is_local_sock);
        let data = if need_encrypt {
            match self.encryptor.encrypt(data) {
                Some(data) => data,
                _ => {
                    error!("{} encrypt data failed", processor2str!(self));
                    return need_destroy!(self);
                }
            }
        } else {
            data.to_vec()
        };

        let (any_error, uncomplete_len) = {
            macro_rules! write {
                ($sock:expr) => (
                    {
                        let mut sock = $sock.take().unwrap();
                        let result = match sock.try_write(&data) {
                            Ok(None) => (false, data.len()),
                            Ok(Some(size)) => {
                                if is_local_sock {
                                    debug!("writed {} bytes to local socket of {}", size, processor2str!(self));
                                } else {
                                    debug!("writed {} bytes to remote socket of {}", size, processor2str!(self));
                                }
                                (false, data.len() - size)
                            }
                            Err(e) => {
                                if is_local_sock {
                                    error!("{} write to local socket error: {}", processor2str!(self), e);
                                } else {
                                    error!("{} write to remote socket error: {}", processor2str!(self), e);
                                }
                                (true, data.len())
                            }
                        };

                        $sock = Some(sock);
                        result
                    }
                );
            }

            if is_local_sock {
                write!(self.local_sock)
            } else {
                write!(self.remote_sock)
            }
        };

        if any_error {
            need_destroy!(self)
        } else if uncomplete_len > 0 {
            let offset = data.len() - uncomplete_len;
            let remain = &data[offset..];
            if is_local_sock {
                self.data_to_write_to_local.extend_from_slice(remain);
            } else {
                self.data_to_write_to_remote.extend_from_slice(remain);
            }
            self.change_interest_to_rw();
            ProcessResult::Success
        } else {
            ProcessResult::Success
        }
    }

    fn handle_stage_stream(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        trace!("handle stage stream: {}", processor2str!(self));
        self.write_to_sock(data, false)
    }

    fn handle_stage_connecting(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        trace!("handle stage connecting: {}", processor2str!(self));
        self.data_to_write_to_remote.extend_from_slice(data);
        ProcessResult::Success
    }

    fn handle_stage_addr(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        trace!("handle stage addr: {}", processor2str!(self));
        let data = if cfg!(feature = "is_client") {
            match data[1] {
                CMD_UDP_ASSOCIATE => {
                    self.stage = HandleStage::UDPAssoc;
                    unimplemented!();
                }
                CMD_CONNECT => {
                    &data[3..]
                }
                cmd => {
                    error!("unknown socks command: {}", cmd);
                    return need_destroy!(self);
                }
            }
        } else {
            data
        };

        match parse_header(data) {
            Some((_addr_type, remote_address, remote_port, header_length)) => {
                self.stage = HandleStage::DNS;

                if cfg!(feature = "is_client") {
                    let response = &[0x05, 0x00, 0x00, 0x01,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x10, 0x10];
                    try_process!(self.write_to_sock(response, true));
                    self.data_to_write_to_remote.extend_from_slice(data);
                    self.server_address = self.choose_a_server();
                } else {
                    if data.len() > header_length {
                        self.data_to_write_to_remote.extend_from_slice(&data[header_length..]);
                    }
                    self.server_address = Some((remote_address, remote_port));
                };

                let token = self.get_id();
                let remote_hostname = if let Some(ref server) = self.server_address {
                    server.0.clone()
                } else {
                    unreachable!();
                };

                let resolved = self.dns_resolver.borrow_mut().resolve(token, remote_hostname);
                match resolved {
                    (None, None) => ProcessResult::Success,
                    (hostname_ip, errmsg) => self.handle_dns_resolved(event_loop, hostname_ip, errmsg),
                }
            }
            None => {
                error!("can not parse socks header");
                need_destroy!(self)
            }
        }
    }

    fn handle_stage_init(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        trace!("handle stage init: {}", processor2str!(self));
        match self.check_auth_method(data) {
            CheckAuthResult::Success => {
                try_process!(self.write_to_sock(&[0x05, 0x00], true));
                self.stage = HandleStage::Addr;
                ProcessResult::Success
            }
            CheckAuthResult::BadSocksHeader => {
                need_destroy!(self)
            }
            CheckAuthResult::NoAcceptableMethods => {
                self.write_to_sock(&[0x05, 0xff], true);
                need_destroy!(self)
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

        if noauto_exist {
            CheckAuthResult::Success
        } else {
            warn!("none of socks method's requested by client is supported");
            CheckAuthResult::NoAcceptableMethods
        }
    }

    fn on_local_read(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        match self.receive_data(true) {
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

    fn on_remote_read(&mut self, _event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        match self.receive_data(false) {
            (Some(data), ProcessResult::Success) => {
                self.write_to_sock(&data, true)
            }
            (_, result @ ProcessResult::Failed(_)) => result,
            _ => ProcessResult::Success
        }
    }

    fn on_write(&mut self, _event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> ProcessResult<Vec<Token>> {
        macro_rules! get_buf_len {
            () => (
                if is_local_sock {
                    self.data_to_write_to_local.len()
                } else {
                    self.data_to_write_to_remote.len()
                }
            );
        }

        let result = if get_buf_len!() > 0 {
            self.send_buf_data(is_local_sock)
        } else {
            ProcessResult::Success
        };

        if get_buf_len!() == 0 {
            self.change_interest_to_r();
        }

        result
    }

    fn on_local_write(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        self.on_write(event_loop, true)
    }

    fn on_remote_write(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        self.stage = HandleStage::Stream;
        self.on_write(event_loop, false)
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
        trace!("{} handle_dns_resolved: {:?}", processor2str!(self), hostname_ip);
        if let Some(errmsg) = errmsg {
            error!("{} resolve DNS error: {}", processor2str!(self), errmsg);
            return need_destroy!(self);
        }

        match hostname_ip {
            Some((_hostname, ip)) => {
                self.stage = HandleStage::Connecting;
                let port = if let Some(ref server) = self.server_address {
                    server.1
                } else {
                    unreachable!();
                };

                match self.create_connection(&ip, port) {
                    Ok(sock) => {
                        info!("connected {}-{} to {}:{}", address2str(&self.client_address),
                                                          processor2str!(self),
                                                          ip, port);
                        self.remote_sock = Some(sock);
                        self.register(event_loop, false);
                        ProcessResult::Success
                    }
                    Err(e) => {
                        error!("connected {}-{} to {}:{} failed: {}", address2str(&self.client_address),
                                                                      processor2str!(self),
                                                                      ip, port, e);
                        need_destroy!(self)
                    }
                }
            }
            _ => need_destroy!(self),
        }
    }
}

impl Processor for TCPProcessor {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>,
               token: Token,
               events: EventSet)
               -> ProcessResult<Vec<Token>> {
        trace!("current handle stage of {} is {:?}", processor2str!(self), self.stage);
        if Some(token) == self.local_token {
            if events.is_error() {
                let sock = self.local_sock.take().unwrap();
                error!("events error on local {}: {}", processor2str!(self),
                                                       sock.take_socket_error().unwrap_err());
                return need_destroy!(self);
            }
            debug!("got events for local {}: {:?}", processor2str!(self), events);

            if events.is_readable() || events.is_hup() {
                try_process!(self.on_local_read(event_loop));
            }

            if events.is_writable() {
                try_process!(self.on_local_write(event_loop));
            }

            self.reregister(event_loop, true);
        } else if Some(token) == self.remote_token {
            if events.is_error() {
                let sock = self.remote_sock.take().unwrap();
                error!("events error on remote {}: {}", processor2str!(self),
                                                        sock.take_socket_error().unwrap_err());
                return need_destroy!(self);
            }
            debug!("got events for remote {}: {:?}", processor2str!(self), events);

            if events.is_readable() || events.is_hup() {
                try_process!(self.on_remote_read(event_loop));
            }

            if events.is_writable() {
                try_process!(self.on_remote_write(event_loop));
            }

            self.reregister(event_loop, false);
        }

        ProcessResult::Success
    }

    fn destroy(&mut self, _event_loop: &mut EventLoop<Relay>) {
        trace!("destroy processor {}", processor2str!(self));

        if let Some(ref sock) = self.local_sock {
            if let Err(e) = sock.shutdown(Shutdown::Both) {
                match e.kind() {
                    ErrorKind::NotConnected => { }
                    _ => {
                        error!("shutdown local {} failed: {}", processor2str!(self), e);
                    }
                }
            }
        }

        if let Some(ref sock) = self.remote_sock {
            if let Err(e) = sock.shutdown(Shutdown::Both) {
                match e.kind() {
                    ErrorKind::NotConnected => { }
                    _ => {
                        error!("shutdown remote {} failed: {}", processor2str!(self), e);
                    }
                }
            }
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
