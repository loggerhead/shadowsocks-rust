use std::io;
use std::fmt;
use std::ops::BitAnd;
use std::borrow::{Cow, Borrow};
use std::io::{Read, Write};

use mio::tcp::{TcpStream, Shutdown};
use mio::{EventLoop, Token, Timeout, EventSet, PollOpt};

use mode::{ServerChooser, Address};
use socks5;
use socks5::{addr_type, Socks5Header};
use util::{RcCell, shift_vec};
use config::Config;
use crypto::Encryptor;
use asyncdns::{Caller, DNSResolver, HostIpPair};
use network::{pair2addr, NetworkWriteBytes};
use socks5::{pack_addr, parse_header, check_auth_method, CheckAuthResult};
use error;
use error::{Result, SocketError, ProcessError, Socks5Error};
use super::Relay;

pub struct TcpProcessor {
    conf: Config,
    stage: HandleStage,
    dns_resolver: RcCell<DNSResolver>,
    server_chooser: RcCell<ServerChooser>,
    timeout: Option<Timeout>,
    local_token: Token,
    local_sock: TcpStream,
    remote_token: Token,
    remote_sock: Option<TcpStream>,
    local_interest: EventSet,
    remote_interest: EventSet,
    local_buf: Option<Vec<u8>>,
    remote_buf: Option<Vec<u8>>,
    client_address: Address,
    server_address: Option<Address>,
    remote_hostname: Option<String>,
    encryptor: Encryptor,
    downstream_status: StreamStatus,
    upstream_status: StreamStatus,
}

impl TcpProcessor {
    pub fn new(local_token: Token,
               remote_token: Token,
               conf: Config,
               local_sock: TcpStream,
               dns_resolver: RcCell<DNSResolver>,
               server_chooser: RcCell<ServerChooser>)
               -> Result<TcpProcessor> {
        let stage = if cfg!(feature = "sslocal") {
            HandleStage::Handshake1
        } else {
            HandleStage::Handshake3
        };

        let encryptor = Encryptor::new(conf["password"].as_str().unwrap(),
                                       conf["encrypt_method"].as_str().unwrap())
            .map_err(|e| ProcessError::InitEncryptorFailed(e))?;

        // TODO: this is a bug of mio 0.5.x (fixed in mio 0.6.x)
        let client_address = if cfg!(windows) {
            Address("?".to_string(), 0)
        } else {
            local_sock.peer_addr()
                .map(|addr| Address(addr.ip().to_string(), addr.port()))?
        };

        local_sock.set_nodelay(true)?;

        Ok(TcpProcessor {
            conf: conf,
            stage: stage,
            dns_resolver: dns_resolver,
            server_chooser: server_chooser,
            timeout: None,
            local_token: local_token,
            local_sock: local_sock,
            remote_token: remote_token,
            remote_sock: None,
            local_buf: None,
            remote_buf: None,
            client_address: client_address,
            server_address: None,
            remote_hostname: None,
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
                debug!("registered {:?} {:?} socket with {:?}",
                       self,
                       self.sock_desc(is_local_sock),
                       events);
            })
            .map_err(|e| From::from(e))
    }

    pub fn register(&mut self,
                    event_loop: &mut EventLoop<Relay>,
                    is_local_sock: bool)
                    -> Result<()> {
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

    fn record_activity(&self) {
        match self.stage {
            HandleStage::Handshake3 |
            HandleStage::Connecting |
            HandleStage::Stream => {
                self.server_chooser.borrow_mut().record(self.get_id(),
                                                        self.server_address.clone().unwrap(),
                                                        self.remote_hostname.as_ref().unwrap());
            }
            _ => {}
        }
    }

    fn update_activity(&self) {
        match self.stage {
            HandleStage::Handshake3 |
            HandleStage::Connecting |
            HandleStage::Stream => {
                self.server_chooser.borrow_mut().update(self.get_id(),
                                                        self.server_address.clone().unwrap(),
                                                        self.remote_hostname.as_ref().unwrap());
            }
            _ => {}
        }
    }

    fn receive_data(&mut self, is_local_sock: bool) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(BUF_SIZE);
        new_fat_slice_from_vec!(buf_slice, buf);

        // to avoid the stupid borrow error
        {
            let res = self.get_sock(is_local_sock).read(buf_slice);
            match res {
                Ok(nread) => {
                    if cfg!(feature = "sslocal") && !is_local_sock {
                        self.update_activity();
                    }
                    unsafe {
                        buf.set_len(nread);
                    }
                }
                Err(e) => return err_from!(SocketError::ReadFailed(e)),
            }

            // no read received which means client closed
            if buf.is_empty() {
                return err_from!(SocketError::ConnectionClosed);
            }
        }

        if (cfg!(feature = "sslocal") && !is_local_sock) ||
           (!cfg!(feature = "sslocal") && is_local_sock) {
            self.encryptor.decrypt(&buf).ok_or(From::from(ProcessError::DecryptFailed))
        } else {
            Ok(buf)
        }
    }

    fn write_to_sock(&mut self, data: &[u8], is_local_sock: bool) -> Result<usize> {
        let nwrite =
            self.get_sock(is_local_sock).write(data).map_err(|e| SocketError::WriteFailed(e))?;
        if cfg!(feature = "sslocal") && !is_local_sock {
            self.record_activity();
        }
        Ok(nwrite)
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
                    let nwrite = self.write_to_sock(data, REMOTE)?;
                    if nwrite < data.len() {
                        self.extend_buf(&data[nwrite..], REMOTE);
                    }
                    self.update_stream_depend_on(data.len() == nwrite, REMOTE);
                    Ok(())
                }
                None => err_from!(ProcessError::EncryptFailed),
            }
        } else {
            let nwrite = self.write_to_sock(data, REMOTE)?;
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
                None => return err_from!(ProcessError::EncryptFailed),
            }
        } else {
            self.extend_buf(data, REMOTE);
        }

        Ok(())
    }

    fn handle_udp_handshake(&mut self) -> Result<()> {
        trace!("udp associate handshake");
        self.stage = HandleStage::UDPAssoc;

        let addr = self.local_sock.local_addr()?;
        let packed_addr = pack_addr(addr.ip());
        let mut packed_port = Vec::<u8>::new();
        try_pack!(u16, packed_port, addr.port());

        let mut header = Vec::with_capacity(32);
        // IPv4 header
        header.extend_from_slice(&[0x05, 0x00, 0x00]);
        header.extend_from_slice(&packed_addr);
        header.extend_from_slice(&packed_port);

        self.local_sock.write_all(&header)?;

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
            err_from!(ProcessError::NotOneTimeAuthSession)
        } else {
            Ok(is_ota_session)
        }
    }

    fn handle_stage_handshake1(&mut self,
                               _event_loop: &mut EventLoop<Relay>,
                               data: &[u8])
                               -> Result<()> {
        trace!("{:?} handle stage handshake1", self);

        match check_auth_method(data) {
            CheckAuthResult::Success => {
                self.write_to_sock(&[0x05, 0x00], LOCAL)?;
                self.stage = HandleStage::Handshake2;
                Ok(())
            }
            CheckAuthResult::BadSocksHeader => {
                err_from!(Socks5Error::CheckAuthFailed(CheckAuthResult::BadSocksHeader))
            }
            CheckAuthResult::NoAcceptableMethods => {
                self.write_to_sock(&[0x05, 0xff], LOCAL)?;
                err_from!(Socks5Error::CheckAuthFailed(CheckAuthResult::NoAcceptableMethods))
            }
        }
    }

    // spec `replies` section of https://www.ietf.org/rfc/rfc1928.txt
    fn handle_stage_handshake2(&mut self,
                               event_loop: &mut EventLoop<Relay>,
                               mut data: &[u8])
                               -> Result<()> {
        trace!("{:?} handle stage handshake2", self);

        if cfg!(feature = "sslocal") {
            match data[1] {
                socks5::cmd::UDP_ASSOCIATE => return self.handle_udp_handshake(),
                socks5::cmd::CONNECT => data = &data[3..],
                cmd => return err_from!(Socks5Error::UnknownCmd(cmd)),
            }

            // +----+-----+-------+------+----------+----------+
            // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            // +----+-----+-------+------+----------+----------+
            // |05  | 00  |  00   |  01  | 00000000 |   0000   |
            // +----+-----+-------+------+----------+----------+
            //                             fake ip   fake port
            let response = &[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            self.write_to_sock(response, LOCAL)?;
        }

        if data.is_empty() {
            self.stage = HandleStage::Handshake3;
            Ok(())
        } else {
            self.handle_stage_handshake3(event_loop, data)
        }
    }

    fn handle_stage_handshake3(&mut self,
                               event_loop: &mut EventLoop<Relay>,
                               data: &[u8])
                               -> Result<()> {
        trace!("{:?} handle stage handshake3", self);
        let Socks5Header(addr_type, remote_address, remote_port, header_length) =
            parse_header(data).ok_or(Socks5Error::InvalidHeader)?;
        info!("connecting to {}:{}", remote_address, remote_port);

        let is_ota_session = self.check_one_time_auth(addr_type)?;
        let data = if is_ota_session {
            match self.encryptor
                .enable_ota(addr_type | addr_type::AUTH, header_length, &data) {
                Some(ota_data) => Cow::Owned(ota_data),
                None => return err_from!(ProcessError::EnableOneTimeAuthFailed),
            }
        } else {
            Cow::Borrowed(data)
        };

        self.update_stream(StreamDirection::Up, StreamStatus::WaitWriting);
        self.stage = HandleStage::Dns;
        // send socks5 response to client
        if cfg!(feature = "sslocal") {
            self.update_stream(StreamDirection::Down, StreamStatus::WaitReading);

            match self.encryptor.encrypt(data.borrow()) {
                Some(ref data) => self.extend_buf(data, REMOTE),
                None => return err_from!(ProcessError::EncryptFailed),
            }

            let server_address = self.server_chooser.borrow_mut().choose(&remote_address);
            match server_address {
                Some(address) => {
                    self.remote_hostname = Some(remote_address);
                    self.server_address = Some(address);
                }
                None => return err_from!(ProcessError::NoServerAvailable),
            }
        } else {
            // buffer data
            if is_ota_session {
                self.extend_buf(&data, REMOTE);
            } else if data.len() > header_length {
                self.extend_buf(&data[header_length..], REMOTE);
            }

            self.server_address = Some(Address(remote_address, remote_port));
        }

        let token = self.get_id();
        let remote_hostname = self.server_address.as_ref().map(|addr| addr.0.clone()).unwrap();
        let resolved = self.dns_resolver.borrow_mut().resolve(token, remote_hostname);
        match resolved {
            Ok(None) => {}
            // if hostname is resolved immediately
            res => self.handle_dns_resolved(event_loop, res),
        }
        Ok(())
    }

    fn on_local_read(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        let data = self.receive_data(LOCAL)?;
        self.reset_timeout(event_loop);
        match self.stage {
            HandleStage::Handshake1 => self.handle_stage_handshake1(event_loop, &data),
            HandleStage::Handshake2 => self.handle_stage_handshake2(event_loop, &data),
            HandleStage::Handshake3 => self.handle_stage_handshake3(event_loop, &data),
            HandleStage::Connecting => self.handle_stage_connecting(event_loop, &data),
            HandleStage::Stream => self.handle_stage_stream(event_loop, &data),
            _ => Ok(()),
        }
    }

    // remote_sock <= data
    fn on_remote_read(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        let data = self.receive_data(REMOTE)?;
        self.reset_timeout(event_loop);

        let data = if cfg!(feature = "sslocal") {
            data
        } else {
            match self.encryptor.encrypt(&data) {
                Some(encrypted) => encrypted,
                None => return err_from!(ProcessError::EncryptFailed),
            }
        };

        // buffer unfinished bytes
        let nwrite = self.write_to_sock(&data, LOCAL)?;
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
            let nwrite = self.write_to_sock(&buf, is_local_sock)?;
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
        let addr = pair2addr(&ip, port)?;
        Ok(TcpStream::connect(&addr)?)
    }

    pub fn handle_events(&mut self,
                         event_loop: &mut EventLoop<Relay>,
                         token: Token,
                         events: EventSet)
                         -> Result<()> {
        debug!("current handle stage of {:?} is {:?}", self, self.stage);

        if token == self.local_token {
            if events.is_error() {
                let e = self.local_sock.take_socket_error().unwrap_err();
                if e.kind() != io::ErrorKind::ConnectionReset {
                    error!("events error on local socket of {:?}: {}", self, e);
                    return err_from!(SocketError::EventError);
                } else {
                    return err_from!(SocketError::ConnectionClosed);
                }
            }
            debug!("{:?} events for local socket {:?}", events, self);

            if events.is_readable() || events.is_hup() {
                self.on_local_read(event_loop)?;
            }
            if events.is_writable() {
                self.on_local_write(event_loop)?;
            }
            self.reregister(event_loop, LOCAL)
        } else if token == self.remote_token {
            if events.is_error() {
                let e = self.remote_sock.take().unwrap().take_socket_error().unwrap_err();
                if e.kind() != io::ErrorKind::ConnectionReset {
                    error!("events error on remote socket of {:?}: {}", self, e);
                    return err_from!(SocketError::EventError);
                } else {
                    return err_from!(SocketError::ConnectionClosed);
                }
            }
            debug!("{:?} events for remote socket {:?}", events, self);

            if events.is_readable() || events.is_hup() {
                self.on_remote_read(event_loop)?;
            }
            if events.is_writable() {
                self.on_remote_write(event_loop)?;
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

        if cfg!(feature = "sslocal") {
            self.server_chooser.borrow_mut().punish(self.get_id());
        }

        self.dns_resolver.borrow_mut().remove_caller(self.get_id());
        self.local_interest = EventSet::none();
        self.remote_interest = EventSet::none();
        self.stage = HandleStage::Destroyed;
        (self.local_token, self.remote_token)
    }

    pub fn fetch_error(&mut self) -> Result<()> {
        match self.stage {
            HandleStage::Error(ref mut e) => Err(e.take().unwrap()),
            _ => Ok(()),
        }
    }
}

impl Caller for TcpProcessor {
    fn get_id(&self) -> Token {
        self.remote_token
    }

    fn handle_dns_resolved(&mut self,
                           event_loop: &mut EventLoop<Relay>,
                           res: Result<Option<HostIpPair>>) {
        debug!("{:?} handle dns resolved: {:?}", self, res);

        macro_rules! my_try {
            ($r:expr) => (
                match $r {
                    Ok(r) => r,
                    Err(e) => {
                        self.stage = HandleStage::Error(Some(e));
                        return;
                    }
                }
            )
        }

        if let Some(HostIpPair(_hostname, ip)) = my_try!(res) {
            self.stage = HandleStage::Connecting;
            let port = self.server_address
                .as_ref()
                .map(|addr| addr.1)
                .unwrap();

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
        let Address(ref ip, ref port) = self.client_address;
        write!(f, "{}:{}/tcp", ip, port)
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
    Handshake1,
    Handshake2,
    Handshake3,
    // only sslocal: UDP assoc
    UDPAssoc,
    // DNS resolved, connect to remote
    Dns,
    // still connecting, more data from local received
    Connecting,
    // remote connected, piping local and remote
    Stream,
    Destroyed,
    Error(Option<error::Error>),
}

#[derive(Debug, PartialEq)]
enum StreamDirection {
    Down,
    Up,
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
