use std::fmt;
use std::ops::BitAnd;
use std::borrow::{Cow, Borrow};
use std::io;
use std::io::{Read, Write, Result};

use mio::tcp::{TcpStream, Shutdown};
use mio::{EventLoop, Token, Timeout, EventSet, PollOpt};

use socks5;
use socks5::addr_type;
use util::{RcCell, shift_vec};
use config::Config;
use encrypt::Encryptor;
use asyncdns::{Caller, DNSResolver, HostIpPair};
use network::{pair2socket_addr, NetworkWriteBytes};
use socks5::{pack_addr, parse_header, check_auth_method, CheckAuthResult};
use super::{choose_a_server, Relay};

macro_rules! err {
    (CheckSocks5AuthFailed, $r:expr) => (
        match $r {
            CheckAuthResult::BadSocksHeader => io_err!("bad socks5 header"),
            CheckAuthResult::NoAcceptableMethods => io_err!("no acceptable socks5 methods"),
            _ => unreachable!(),
        }
    );
    (UnknownSocks5Cmd, $cmd:expr) => ( io_err!("unknown socks5 command: {}", $cmd) );
    (InvalidSocks5Header) => ( io_err!("invalid socks5 header") );
    (ConnectionClosed) => (
        io::Error::new(io::ErrorKind::ConnectionReset, "connection closed by the other side")
    );

    ($($arg:tt)*) => ( processor_err!($($arg)*) );
}

pub struct TcpProcessor {
    conf: Config,
    stage: HandleStage,
    dns_resolver: RcCell<DNSResolver>,
    timeout: Option<Timeout>,
    local_token: Token,
    local_sock: TcpStream,
    remote_token: Token,
    remote_sock: Option<TcpStream>,
    local_interest: EventSet,
    remote_interest: EventSet,
    local_buf: Option<Vec<u8>>,
    remote_buf: Option<Vec<u8>>,
    client_address: (String, u16),
    server_address: Option<(String, u16)>,
    encryptor: Encryptor,
    downstream_status: StreamStatus,
    upstream_status: StreamStatus,
}

impl TcpProcessor {
    pub fn new(local_token: Token,
               remote_token: Token,
               conf: Config,
               local_sock: TcpStream,
               dns_resolver: RcCell<DNSResolver>)
               -> Result<TcpProcessor> {
        let stage = if cfg!(feature = "sslocal") {
            HandleStage::Init
        } else {
            HandleStage::Addr
        };
        let encryptor = Encryptor::new(conf["password"].as_str().unwrap());

        let client_address = try!(local_sock.peer_addr().map(|addr| {
            (addr.ip().to_string(), addr.port())
        }));
        try!(local_sock.set_nodelay(true));

        Ok(TcpProcessor {
            conf: conf,
            stage: stage,
            dns_resolver: dns_resolver,
            timeout: None,
            local_token: local_token,
            local_sock: local_sock,
            remote_token: remote_token,
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
        })
    }

    fn sock_desc(&self, is_local_sock: bool) -> &'static str {
        if is_local_sock { "local" } else { "remote" }
    }

    fn get_token(&self, is_local_sock: bool) -> Token {
        if is_local_sock {
            self.local_token
        } else {
            self.remote_token
        }
    }

    fn get_sock(&mut self, is_local_sock: bool) -> &mut TcpStream {
        if is_local_sock {
            &mut self.local_sock
        } else {
            self.remote_sock.as_mut().unwrap()
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

    pub fn reset_timeout(&mut self, event_loop: &mut EventLoop<Relay>) {
        if self.timeout.is_some() {
            let timeout = self.timeout.take().unwrap();
            event_loop.clear_timeout(timeout);
        }
        let delay = self.conf["timeout"].as_integer().unwrap() as u64 * 1000;
        // it's ok if setup timeout failed
        self.timeout = event_loop.timeout_ms(self.get_id(), delay).ok();
    }

    fn update_stream(&mut self, stream: StreamDirection, status: StreamStatus) {
        match stream {
            StreamDirection::Down => self.downstream_status = status,
            StreamDirection::Up => self.upstream_status = status,
        }

        self.local_interest = EventSet::none();
        if self.downstream_status & StreamStatus::WaitWriting {
            self.local_interest = self.local_interest | EventSet::writable();
        }
        if self.upstream_status & StreamStatus::WaitReading {
            self.local_interest = self.local_interest | EventSet::readable();
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

    fn do_register(&mut self,
                   event_loop: &mut EventLoop<Relay>,
                   is_local_sock: bool,
                   is_reregister: bool)
                   -> Result<()> {
        let token = self.get_token(is_local_sock);
        let events = self.get_interest(is_local_sock);
        let pollopts = PollOpt::edge() | PollOpt::oneshot();

        let register_result = if is_reregister {
            event_loop.reregister(self.get_sock(is_local_sock), token, events, pollopts)
        } else {
            event_loop.register(self.get_sock(is_local_sock), token, events, pollopts)
        };

        register_result.map(|_| {
            debug!("registered {:?} {:?} socket with {:?}", self, self.sock_desc(is_local_sock), events);
        })
    }

    pub fn register(&mut self, event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> Result<()> {
        if is_local_sock {
            self.local_interest = EventSet::readable();
        } else {
            self.remote_interest = EventSet::readable() | EventSet::writable();
        }
        self.do_register(event_loop, is_local_sock, REMOTE)
    }

    fn reregister(&mut self, event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> Result<()> {
        self.do_register(event_loop, is_local_sock, LOCAL)
    }

    fn receive_data(&mut self, is_local_sock: bool) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(BUF_SIZE);
        new_fat_slice_from_vec!(buf_slice, buf);

        // to avoid the stupid borrow error
        {
            let mut sock = self.get_sock(is_local_sock);
            match sock.read(buf_slice) {
                Ok(nread) => unsafe { buf.set_len(nread); },
                Err(e) => return Err(err!(ReadFailed, e)),
            }

            // no read received which means client closed
            if buf.is_empty() {
                return Err(err!(ConnectionClosed));
            }
        }

        if (cfg!(feature = "sslocal") && !is_local_sock)
                || (!cfg!(feature = "sslocal") && is_local_sock) {
            self.encryptor.decrypt(&buf).ok_or(err!(DecryptFailed))
        } else {
            Ok(buf)
        }
    }

    fn write_to_sock(&mut self, data: &[u8], is_local_sock: bool) -> Result<usize> {
        let sock = self.get_sock(is_local_sock);
        sock.write(data).map_err(|e| err!(WriteFailed, e))
    }

    // data => remote_sock => ssserver/server
    fn handle_stage_stream(&mut self,
                           _event_loop: &mut EventLoop<Relay>,
                           data: &[u8])
                           -> Result<()> {
        trace!("{:?} handle stage stream", self);

        if cfg!(feature = "sslocal") {
            match self.encryptor.encrypt(data) {
                Some(ref data) => {
                    let nwrite = try!(self.write_to_sock(data, REMOTE));
                    if nwrite < data.len() {
                        self.extend_buf(&data[nwrite..], REMOTE);
                    }
                    self.update_stream_depend_on(data.len() == nwrite, REMOTE);
                    Ok(())
                }
                None => Err(err!(EncryptFailed)),
            }
        } else {
            let nwrite = try!(self.write_to_sock(data, REMOTE));
            if nwrite < data.len() {
                self.extend_buf(&data[nwrite..], REMOTE);
            }
            self.update_stream_depend_on(data.len() == nwrite, REMOTE);
            Ok(())
        }
    }

    fn handle_stage_connecting(&mut self,
                               _event_loop: &mut EventLoop<Relay>,
                               data: &[u8])
                               -> Result<()> {
        trace!("{:?} handle stage connecting", self);

        if cfg!(feature = "sslocal") {
            match self.encryptor.encrypt(data) {
                Some(ref data) => self.extend_buf(data, REMOTE),
                None => return Err(err!(EncryptFailed)),
            }
        } else {
            self.extend_buf(data, REMOTE);
        }

        Ok(())
    }

    fn handle_udp_handshake(&mut self) -> Result<()> {
        trace!("udp associate handshake");
        self.stage = HandleStage::UDPAssoc;

        let addr = try!(self.local_sock.local_addr());
        let packed_addr = pack_addr(addr.ip());
        let mut packed_port = Vec::<u8>::new();
        try_pack!(u16, packed_port, addr.port());

        let mut header = Vec::with_capacity(32);
        // IPv4 header
        header.extend_from_slice(&[0x05, 0x00, 0x00]);
        header.extend_from_slice(&packed_addr);
        header.extend_from_slice(&packed_port);

        try!(self.local_sock.write_all(&header));

        Ok(())
    }

    fn check_one_time_auth(&mut self, addr_type: u8) -> Result<bool> {
        let is_ota_enabled = self.conf.get_bool("one_time_auth").unwrap_or(false);
        let is_ota_session = if cfg!(feature = "sslocal") {
            is_ota_enabled
        } else {
            addr_type & addr_type::AUTH == addr_type::AUTH
        };

        // if ssserver enabled OTA but client not
        if !cfg!(feature = "sslocal") && is_ota_enabled && !is_ota_session {
            Err(err!(NotOneTimeAuthSession))
        } else {
            Ok(is_ota_session)
        }
    }

    // spec `replies` section of https://www.ietf.org/rfc/rfc1928.txt
    fn handle_stage_addr(&mut self,
                         event_loop: &mut EventLoop<Relay>,
                         mut data: &[u8])
                         -> Result<()> {
        trace!("{:?} handle stage addr", self);

        if cfg!(feature = "sslocal") {
            match data[1] {
                socks5::cmd::UDP_ASSOCIATE => return self.handle_udp_handshake(),
                socks5::cmd::CONNECT => data = &data[3..],
                cmd => return Err(err!(UnknownSocks5Cmd, cmd)),
            }
        }

        // parse socks5 header
        match parse_header(data) {
            Some((addr_type, remote_address, remote_port, header_length)) => {
                info!("connecting to {}:{}", remote_address, remote_port);
                let is_ota_session = try!(self.check_one_time_auth(addr_type));
                let data = if is_ota_session {
                    match self.encryptor.enable_ota(addr_type | addr_type::AUTH, header_length, &data) {
                        Some(ota_data) => Cow::Owned(ota_data),
                        None => return Err(err!(EnableOneTimeAuthFailed)),
                    }
                } else {
                    Cow::Borrowed(data)
                };

                self.update_stream(StreamDirection::Up, StreamStatus::WaitWriting);
                self.stage = HandleStage::Dns;
                // send socks5 response to client
                if cfg!(feature = "sslocal") {
                    let response = &[0x05, 0x00, 0x00, 0x01,
                                     // fake ip
                                     0x00, 0x00, 0x00, 0x00,
                                     // fake port
                                     0x00, 0x00];
                    try!(self.write_to_sock(response, LOCAL));
                    self.update_stream(StreamDirection::Down, StreamStatus::WaitReading);

                    match self.encryptor.encrypt(data.borrow()) {
                        Some(ref data) => self.extend_buf(data, REMOTE),
                        None => return Err(err!(EncryptFailed)),
                    }

                    self.server_address = choose_a_server(&self.conf);
                // buffer data
                } else {
                    if is_ota_session {
                        self.extend_buf(&data, REMOTE);
                    } else if data.len() > header_length {
                        self.extend_buf(&data[header_length..], REMOTE);
                    }

                    self.server_address = Some((remote_address, remote_port));
                }

                let token = self.get_id();
                let remote_hostname = self.server_address.as_ref().map(|s| s.0.clone()).unwrap();
                let resolved = self.dns_resolver.borrow_mut().resolve(token, remote_hostname);
                match resolved {
                    Ok(None) => {}
                    // if hostname is resolved immediately
                    res => self.handle_dns_resolved(event_loop, res),
                }
                Ok(())
            }
            None => {
                Err(err!(InvalidSocks5Header))
            }
        }
    }

    fn handle_stage_init(&mut self, _event_loop: &mut EventLoop<Relay>, data: &[u8]) -> Result<()> {
        trace!("{:?} handle stage init", self);

        match check_auth_method(data) {
            CheckAuthResult::Success => {
                try!(self.write_to_sock(&[0x05, 0x00], LOCAL));
                self.stage = HandleStage::Addr;
                Ok(())
            }
            CheckAuthResult::BadSocksHeader => {
                Err(err!(CheckSocks5AuthFailed, CheckAuthResult::BadSocksHeader))
            }
            CheckAuthResult::NoAcceptableMethods => {
                try!(self.write_to_sock(&[0x05, 0xff], LOCAL));
                Err(err!(CheckSocks5AuthFailed, CheckAuthResult::NoAcceptableMethods))
            }
        }
    }

    fn on_local_read(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        let data = try!(self.receive_data(LOCAL));
        self.reset_timeout(event_loop);
        match self.stage {
            HandleStage::Init => self.handle_stage_init(event_loop, &data),
            HandleStage::Addr => self.handle_stage_addr(event_loop, &data),
            HandleStage::Connecting => self.handle_stage_connecting(event_loop, &data),
            HandleStage::Stream => self.handle_stage_stream(event_loop, &data),
            _ => Ok(())
        }
    }

    // remote_sock <= data
    fn on_remote_read(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        let data = try!(self.receive_data(REMOTE));
        self.reset_timeout(event_loop);

        let data = if !cfg!(feature = "sslocal") {
            match self.encryptor.encrypt(&data) {
                Some(encrypted) => encrypted,
                None => return Err(err!(EncryptFailed)),
            }
        } else {
            data
        };

        // buffer unfinished bytes
        let nwrite = try!(self.write_to_sock(&data, LOCAL));
        if nwrite < data.len() {
            self.extend_buf(&data[nwrite..], LOCAL);
        }
        self.update_stream_depend_on(data.len() == nwrite, LOCAL);
        Ok(())
    }

    fn on_write(&mut self, _event_loop: &mut EventLoop<Relay>, is_local_sock: bool) -> Result<()> {
        if self.check_buf_empty(is_local_sock) {
            if is_local_sock {
                self.update_stream(StreamDirection::Down, StreamStatus::WaitReading);
            } else {
                self.update_stream(StreamDirection::Up, StreamStatus::WaitReading);
            }
        } else {
            let mut buf = self.get_buf(is_local_sock);
            let nwrite = try!(self.write_to_sock(&buf, is_local_sock));
            shift_vec(&mut buf, nwrite);
            self.update_stream_depend_on(buf.len() == nwrite, is_local_sock);
            self.set_buf(buf, is_local_sock);
        }
        Ok(())
    }

    fn on_local_write(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        self.on_write(event_loop, LOCAL)
    }

    fn on_remote_write(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        self.stage = HandleStage::Stream;
        self.on_write(event_loop, REMOTE)
    }

    fn create_connection(&mut self, ip: &str, port: u16) -> Result<TcpStream> {
        pair2socket_addr(ip, port).ok_or(err!(ParseAddrFailed)).and_then(|addr| {
            TcpStream::connect(&addr)
        })
    }

    pub fn process(&mut self, event_loop: &mut EventLoop<Relay>,
                   token: Token,
                   events: EventSet)
                   -> Result<()> {
        debug!("current handle stage of {:?} is {:?}", self, self.stage);

        if token == self.local_token {
            if events.is_error() {
                let e = self.local_sock.take_socket_error().unwrap_err();
                if e.kind() != io::ErrorKind::ConnectionReset {
                    error!("events error on local socket of {:?}: {}", self, e);
                    return Err(err!(EventError));
                } else {
                    return Err(err!(ConnectionClosed));
                }
            }
            debug!("{:?} events for local socket {:?}", events, self);

            if events.is_readable() || events.is_hup() {
                try!(self.on_local_read(event_loop));
            }
            if events.is_writable() {
                try!(self.on_local_write(event_loop));
            }
            self.reregister(event_loop, LOCAL)
        } else if token == self.remote_token {
            if events.is_error() {
                let e = self.remote_sock.take().unwrap().take_socket_error().unwrap_err();
                if e.kind() != io::ErrorKind::ConnectionReset {
                    error!("events error on remote socket of {:?}: {}", self, e);
                    return Err(err!(EventError));
                } else {
                    return Err(err!(ConnectionClosed));
                }
            }
            debug!("{:?} events for remote socket {:?}", events, self);

            if events.is_readable() || events.is_hup() {
                try!(self.on_remote_read(event_loop));
            }
            if events.is_writable() {
                try!(self.on_remote_write(event_loop));
            }
            self.reregister(event_loop, REMOTE)
        } else {
            unreachable!();
        }
    }

    pub fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) -> (Token, Token) {
        debug!("destroy {:?}", self);

        if let Err(e) = self.local_sock.shutdown(Shutdown::Both) {
            if e.kind() != io::ErrorKind::NotConnected {
                error!("shutdown local socket {:?} failed: {}", self, e);
            }
        }

        if let Some(sock) = self.remote_sock.take() {
            if let Err(e) = sock.shutdown(Shutdown::Both) {
                if e.kind() != io::ErrorKind::NotConnected {
                    error!("shutdown remote socket {:?} failed: {}", self, e);
                }
            }
        }

        if let Some(timeout) = self.timeout.take() {
            event_loop.clear_timeout(timeout);
        }

        self.dns_resolver.borrow_mut().remove_caller(self.get_id());
        self.local_interest = EventSet::none();
        self.remote_interest = EventSet::none();
        self.stage = HandleStage::Destroyed;
        (self.local_token, self.remote_token)
    }

    pub fn fetch_error(&self) -> Result<()> {
        match self.stage {
            HandleStage::Error(ref e) => Err(err!(DnsResolveFailed, e)),
            _ => Ok(()),
        }
    }
}

impl Caller for TcpProcessor {
    fn get_id(&self) -> Token {
        self.remote_token
    }

    fn handle_dns_resolved(&mut self, event_loop: &mut EventLoop<Relay>, res: Result<Option<HostIpPair>>) {
        debug!("{:?} handle dns resolved: {:?}", self, res);

        macro_rules! my_try {
            ($r:expr) => (
                match $r {
                    Ok(r) => r,
                    Err(e) => {
                        self.stage = HandleStage::Error(e);
                        return;
                    }
                }
            )
        }

        if let Some((_hostname, ip)) = my_try!(res) {
            self.stage = HandleStage::Connecting;
            let port = self.server_address.as_ref().map(|addr| {
                addr.1
            }).unwrap();

            let sock = my_try!(self.create_connection(&ip, port));
            self.remote_sock = Some(sock);
            my_try!(self.register(event_loop, REMOTE));
            self.update_stream(StreamDirection::Up, StreamStatus::WaitBoth);
            self.update_stream(StreamDirection::Down, StreamStatus::WaitReading);
            my_try!(self.reregister(event_loop, LOCAL));
        } else {
            error!("resolve dns failed: empty response");
        }
    }
}

impl fmt::Debug for TcpProcessor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}/tcp", self.client_address.0, self.client_address.1)
    }
}

const BUF_SIZE: usize = 32 * 1024;
pub const LOCAL: bool = true;
pub const REMOTE: bool = false;

// for each opening port, we have a TcpRelay
// for each connection, we have a TcpProcessor to handle the connection
//
// for each handler, we have 2 sockets:
//    local:   connected to the client
//    remote:  connected to remote server

// for each handler, it could be at one of several stages:
#[derive(Debug)]
enum HandleStage {
    // only sslocal: auth METHOD received from local, reply with selection message
    Init,
    // addr received from local, query DNS for remote
    Addr,
    // only sslocal: UDP assoc
    UDPAssoc,
    // DNS resolved, connect to remote
    Dns,
    // still connecting, more data from local received
    Connecting,
    // remote connected, piping local and remote
    Stream,
    Destroyed,
    Error(io::Error),
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
