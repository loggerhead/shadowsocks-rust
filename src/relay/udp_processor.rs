use std::io;
use std::io::Result;
use std::fmt;
use std::net::SocketAddr;

use mio::udp::UdpSocket;
use mio::{EventSet, Token, Timeout, EventLoop, PollOpt};

use util::RcCell;
use config::Config;
use collections::Dict;
use encrypt::Encryptor;
use socks5::{parse_header, pack_addr, addr_type};
use network::{str2addr4, NetworkWriteBytes};
use asyncdns::{Caller, DNSResolver, HostIpPair};
use super::Relay;

type Socks5Requests = Vec<Vec<u8>>;
type PortRequestMap = Dict<u16, Socks5Requests>;

macro_rules! err {
    (InvalidSocks5Header) => ( io_err!("invalid socks5 header") );
    (UnknownHost, $host:expr) => ( io_err!("cannot find relevant request of {}", $host) );

    ($($arg:tt)*) => ( processor_err!($($arg)*) );
}


pub struct UdpProcessor {
    token: Token,
    conf: Config,
    stage: HandleStage,
    interest: EventSet,
    timeout: Option<Timeout>,
    addr: SocketAddr,
    sock: UdpSocket,
    relay_sock: RcCell<UdpSocket>,
    receive_buf: Option<Vec<u8>>,
    requests: Dict<String, PortRequestMap>,
    dns_resolver: RcCell<DNSResolver>,
    encryptor: RcCell<Encryptor>,
}

impl UdpProcessor {
    pub fn new(token: Token,
               conf: Config,
               addr: SocketAddr,
               relay_sock: RcCell<UdpSocket>,
               dns_resolver: RcCell<DNSResolver>,
               encryptor: RcCell<Encryptor>)
               -> Result<UdpProcessor> {
        let sock = try!(UdpSocket::v4().map_err(|_| err!(InitSocketFailed)));

        Ok(UdpProcessor {
            token: token,
            conf: conf,
            stage: HandleStage::Init,
            interest: EventSet::readable(),
            timeout: None,
            addr: addr,
            sock: sock,
            relay_sock: relay_sock,
            receive_buf: Some(Vec::with_capacity(BUF_SIZE)),
            requests: Dict::default(),
            encryptor: encryptor,
            dns_resolver: dns_resolver,
        })
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    pub fn reset_timeout(&mut self, event_loop: &mut EventLoop<Relay>) {
        if self.timeout.is_some() {
            let timeout = self.timeout.take().unwrap();
            event_loop.clear_timeout(timeout);
        }
        let delay = self.conf["timeout"].as_integer().unwrap() as u64 * 1000;
        self.timeout = event_loop.timeout_ms(self.get_id(), delay).ok();
    }

    fn do_register(&mut self,
                   event_loop: &mut EventLoop<Relay>,
                   is_reregister: bool)
                   -> Result<()> {
        let token = self.get_id();
        let pollopts = PollOpt::edge() | PollOpt::oneshot();

        let register_result = if is_reregister {
            event_loop.reregister(&self.sock, token, self.interest, pollopts)
        } else {
            event_loop.register(&self.sock, token, self.interest, pollopts)
        };

        register_result.map(|_| {
            debug!("registered {:?} socket with {:?}", self, self.interest);
        })
    }

    pub fn register(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        self.do_register(event_loop, false)
    }

    fn reregister(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        self.do_register(event_loop, true)
    }

    fn add_request(&mut self, server_addr: String, server_port: u16, data: Vec<u8>) {
        if !self.requests.contains_key(&server_addr) {
            self.requests.insert(server_addr.clone(), Dict::default());
        }
        let port_requests_map = self.requests.get_mut(&server_addr).unwrap();
        if !port_requests_map.contains_key(&server_port) {
            port_requests_map.insert(server_port, vec![]);
        }

        port_requests_map.get_mut(&server_port).unwrap().push(data);
    }

    fn send_to(&self,
               is_send_to_client: bool,
               data: &[u8],
               addr: &SocketAddr)
               -> Result<Option<usize>> {
        let res = if is_send_to_client {
            self.sock.send_to(data, addr)
        } else {
            self.relay_sock.borrow().send_to(data, addr)
        };

        res.map_err(|e| err!(WriteFailed, e))
    }

    pub fn handle_data(&mut self,
                       event_loop: &mut EventLoop<Relay>,
                       data: &[u8],
                       addr_type: u8,
                       server_addr: String,
                       server_port: u16,
                       header_length: usize)
                       -> Result<()> {
        trace!("{:?} handle data", self);
        self.stage = HandleStage::Init;
        self.reset_timeout(event_loop);

        let is_ota_enabled = self.conf.get_bool("one_time_auth").unwrap_or(false);
        let request = if cfg!(feature = "sslocal") {
            // if is a OTA session
            if is_ota_enabled {
                self.encryptor.borrow_mut().encrypt_udp_ota(addr_type | addr_type::AUTH, data)
            } else {
                self.encryptor.borrow_mut().encrypt_udp(data)
            }
        } else {
            // if is a OTA session
            if addr_type & addr_type::AUTH == addr_type::AUTH {
                self.encryptor.borrow_mut().decrypt_udp_ota(addr_type, data)
                // if ssserver enabled OTA but client not
            } else if is_ota_enabled {
                return Err(err!(NotOneTimeAuthSession));
            } else {
                // TODO: change to use `Cow`
                Some(data.to_vec())
            }
        };

        if let Some(request) = request {
            if cfg!(feature = "sslocal") {
                self.add_request(server_addr.clone(), server_port, request);
            } else {
                self.add_request(server_addr.clone(),
                                 server_port,
                                 request[header_length..].to_vec());
            }
        } else {
            if cfg!(feature = "sslocal") {
                return Err(err!(EncryptFailed));
            } else {
                return Err(err!(DecryptFailed));
            }
        }

        let resolved = self.dns_resolver.borrow_mut().resolve(self.token, server_addr);
        match resolved {
            Ok(None) => {}
            // if hostname is resolved immediately
            res => self.handle_dns_resolved(event_loop, res),
        }

        Ok(())
    }

    fn on_read(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<Option<usize>> {
        trace!("{:?} handle stage stream", self);
        self.stage = HandleStage::Stream;
        self.reset_timeout(event_loop);

        let mut buf = self.receive_buf.take().unwrap();
        new_fat_slice_from_vec!(buf_slice, buf);

        let res = try!(self.sock.recv_from(buf_slice).map_err(|e| err!(ReadFailed, e)));
        let res = match res {
            None => Ok(None),
            Some((nread, addr)) => {
                unsafe {
                    buf.set_len(nread);
                }

                if cfg!(feature = "sslocal") {
                    match self.encryptor.borrow_mut().decrypt_udp(&buf) {
                        Some(data) => {
                            if parse_header(&data).is_some() {
                                let mut response = Vec::with_capacity(3 + data.len());
                                response.extend_from_slice(&[0u8; 3]);
                                response.extend_from_slice(&data);
                                self.send_to(SERVER, &response, &self.addr)
                            } else {
                                Err(err!(InvalidSocks5Header))
                            }
                        }
                        None => Err(err!(DecryptFailed)),
                    }
                } else {
                    // construct a socks5 request
                    let packed_addr = pack_addr(addr.ip());
                    let mut packed_port = Vec::<u8>::new();
                    try_pack!(u16, packed_port, addr.port());

                    let mut data = Vec::with_capacity(packed_addr.len() + packed_port.len() +
                                                      buf.len());
                    data.extend_from_slice(&packed_addr);
                    data.extend_from_slice(&packed_port);
                    data.extend_from_slice(&buf);

                    match self.encryptor.borrow_mut().encrypt_udp(&data) {
                        Some(response) => self.send_to(SERVER, &response, &self.addr),
                        None => Err(err!(EncryptFailed)),
                    }
                }
            }
        };

        self.receive_buf = Some(buf);
        res
    }

    // send to up stream
    pub fn process(&mut self,
                   event_loop: &mut EventLoop<Relay>,
                   _token: Token,
                   events: EventSet)
                   -> Result<()> {
        debug!("current handle stage of {:?} is {:?}", self, self.stage);

        if events.is_error() {
            error!("{:?} got a events error", self);
            return Err(err!(EventError));
        }

        try!(self.on_read(event_loop));
        self.reregister(event_loop)
    }

    pub fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        debug!("destroy {:?}", self);

        if let Some(timeout) = self.timeout.take() {
            event_loop.clear_timeout(timeout);
        }

        self.dns_resolver.borrow_mut().remove_caller(self.get_id());
        self.interest = EventSet::none();
        self.receive_buf = None;
        self.stage = HandleStage::Destroyed;
    }
}

impl Caller for UdpProcessor {
    fn get_id(&self) -> Token {
        self.token
    }

    fn handle_dns_resolved(&mut self,
                           _event_loop: &mut EventLoop<Relay>,
                           res: Result<Option<HostIpPair>>) {
        debug!("{:?} handle dns resolved: {:?}", self, res);
        self.stage = HandleStage::Dns;

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

        if let Some((hostname, ip)) = my_try!(res) {
            if let Some(port_requests_map) = self.requests.remove(&hostname) {
                for (port, requests) in &port_requests_map {
                    let address = format!("{}:{}", ip, port);
                    let server_addr = my_try!(str2addr4(&address).ok_or(err!(ParseAddrFailed)));

                    for request in requests {
                        my_try!(self.send_to(CLIENT, request, &server_addr));
                    }
                }
            } else {
                self.stage = HandleStage::Error(err!(UnknownHost, hostname));
                return;
            }
        }
    }
}


impl fmt::Debug for UdpProcessor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}/udp", self.addr)
    }
}

const BUF_SIZE: usize = 64 * 1024;
const CLIENT: bool = true;
const SERVER: bool = false;

#[derive(Debug)]
enum HandleStage {
    // only sslocal: auth METHOD received from local, reply with selection message
    Init,
    // DNS resolved, connect to remote
    Dns,
    Stream,
    Destroyed,
    Error(io::Error),
}