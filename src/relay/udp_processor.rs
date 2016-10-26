use std::rc::Rc;
use std::cell::RefCell;
use std::net::SocketAddr;

use mio::udp::UdpSocket;
use mio::{EventSet, Token, Timeout, EventLoop, PollOpt};

use collections::Dict;
use socks5::{parse_header, pack_addr};
use encrypt::Encryptor;
use config::Config;
use network::{str2addr4, NetworkWriteBytes};
use asyncdns::{DNSResolver, Caller};
use super::{Relay, ProcessResult};

type Socks5Requests = Vec<Vec<u8>>;
type PortRequestMap = Dict<u16, Socks5Requests>;

pub struct UdpProcessor {
    conf: Config,
    stage: HandleStage,
    token: Option<Token>,
    interest: EventSet,
    timeout: Option<Timeout>,
    addr: SocketAddr,
    sock: UdpSocket,
    relay_sock: Rc<RefCell<UdpSocket>>,
    receive_buf: Option<Vec<u8>>,
    requests: Dict<String, PortRequestMap>,
    encryptor: Encryptor,
    dns_resolver: Rc<RefCell<DNSResolver>>,
}

impl UdpProcessor {
    pub fn new(conf: Config,
               addr: SocketAddr,
               relay_sock: Rc<RefCell<UdpSocket>>,
               dns_resolver: Rc<RefCell<DNSResolver>>) -> UdpProcessor {
        let encryptor = Encryptor::new(conf["password"].as_str().unwrap());
        let sock = UdpSocket::v4().unwrap();

        UdpProcessor {
            conf: conf,
            stage: HandleStage::Init,
            token: None,
            interest: EventSet::readable(),
            timeout: None,
            addr: addr,
            sock: sock,
            relay_sock: relay_sock,
            receive_buf: Some(Vec::with_capacity(BUF_SIZE)),
            requests: Dict::default(),
            encryptor: encryptor,
            dns_resolver: dns_resolver,
        }
    }

    pub fn set_token(&mut self, token: Token) {
        self.token = Some(token);
    }

    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    fn process_failed(&self) -> ProcessResult<Vec<Token>> {
        ProcessResult::Failed(vec![self.token.unwrap()])
    }

    pub fn reset_timeout(&mut self, event_loop: &mut EventLoop<Relay>) {
        if self.timeout.is_some() {
            let timeout = self.timeout.take().unwrap();
            event_loop.clear_timeout(timeout);
        }
        let delay = self.conf["timeout"].as_integer().unwrap() as u64 * 1000;
        self.timeout = event_loop.timeout_ms(self.get_id(), delay).ok();
    }

    fn do_register(&mut self, event_loop: &mut EventLoop<Relay>, is_reregister: bool) -> bool {
        let token = self.token.unwrap();
        let pollopts = PollOpt::edge() | PollOpt::oneshot();

        let register_result = if is_reregister {
            event_loop.reregister(&self.sock, token, self.interest, pollopts)
        } else {
            event_loop.register(&self.sock, token, self.interest, pollopts)
        };

        match register_result {
            Ok(_) => debug!("udp has registred events {:?}", self.interest),
            Err(ref e) => error!("udp processor register events {:?} failed: {}", self.interest, e),
        }

        register_result.is_ok()
    }

    pub fn register(&mut self, event_loop: &mut EventLoop<Relay>) -> bool {
        self.do_register(event_loop, false)
    }

    fn reregister(&mut self, event_loop: &mut EventLoop<Relay>) -> bool {
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

    fn send_to(&self, is_send_to_client: bool, data: &[u8], addr: &SocketAddr) -> ProcessResult<Vec<Token>> {
        if is_send_to_client {
            if let Err(e) = self.sock.send_to(&data, addr) {
                error!("UDP processor send data failed: {}", e);
                return self.process_failed();
            }
        } else {
            if let Err(e) = self.relay_sock.borrow().send_to(&data, addr) {
                error!("UDP processor send data failed: {}", e);
                return self.process_failed();
            }
        }
        ProcessResult::Success
    }

    pub fn handle_init(&mut self,
                       event_loop: &mut EventLoop<Relay>,
                       data: &[u8],
                       server_addr: String,
                       server_port: u16) -> ProcessResult<Vec<Token>> {
        debug!("UDP processor stage: init");
        self.stage = HandleStage::Init;
        self.reset_timeout(event_loop);
        let request = if cfg!(feature = "sslocal") {
            match self.encryptor.encrypt_udp(&data) {
                Some(data) => data,
                _ => {
                    error!("UDP processor encrypt data failed");
                    return self.process_failed();
                }
            }
        } else {
            Vec::from(data)
        };
        self.add_request(server_addr.clone(), server_port, request);


        // resolve server address by async DNS
        let resolved = self.dns_resolver.borrow_mut().resolve(self.token.unwrap(), server_addr);
        match resolved {
            (None, None) => { }
            // if address is resolved immediately
            (hostname_ip, errmsg) => {
                self.handle_dns_resolved(event_loop, hostname_ip, errmsg);
            }
        }

        ProcessResult::Success
    }

    fn on_read(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        debug!("UDP processor: on_read");
        self.stage = HandleStage::Stream;
        self.reset_timeout(event_loop);
        let mut buf = self.receive_buf.take().unwrap();
        new_fat_slice_from_vec!(buf_slice, buf);

        match self.sock.recv_from(buf_slice) {
            Ok(None) => { }
            Ok(Some((nread, addr))) => {
                unsafe { buf.set_len(nread); }

                if cfg!(feature = "sslocal") {
                    if let Some(data) = self.encryptor.decrypt_udp(&buf) {
                        if parse_header(&data).is_some() {
                            let mut response = Vec::with_capacity(3 + data.len());
                            response.extend_from_slice(&[0u8; 3]);
                            response.extend_from_slice(&data);
                            self.send_to(SERVER, &response, &self.addr);
                        }
                    } else {
                        warn!("decrypt udp data failed");
                    }
                } else {
                    let packed_addr = pack_addr(addr.ip());
                    let mut packed_port = Vec::<u8>::new();
                    let _ = packed_port.put_u16(addr.port());

                    let mut data = Vec::with_capacity(packed_addr.len() + packed_port.len() + buf.len());
                    data.extend_from_slice(&packed_addr);
                    data.extend_from_slice(&packed_port);
                    data.extend_from_slice(&buf);

                    if let Some(response) = self.encryptor.encrypt_udp(&data) {
                        self.send_to(SERVER, &response, &self.addr);
                    } else {
                        warn!("encrypt udp data failed");
                    }
                }
            }
            Err(e) => {
                error!("UDP processor receive data failed: {}", e);
                return self.process_failed();
            }
        }

        self.receive_buf = Some(buf);
        ProcessResult::Success
    }

    // send to up stream
    pub fn process(&mut self,
                   event_loop: &mut EventLoop<Relay>,
                   _token: Token,
                   events: EventSet)
                   -> ProcessResult<Vec<Token>> {
        if events.is_error() {
            error!("UDP processor error");
            return self.process_failed();
        }

        try_process!(self.on_read(event_loop));
        self.reregister(event_loop);
        ProcessResult::Success
    }

    pub fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        if self.timeout.is_some() {
            let timeout = self.timeout.take().unwrap();
            event_loop.clear_timeout(timeout);
        }

        self.dns_resolver.borrow_mut().remove_caller(self.get_id());

        self.token = None;
        self.interest = EventSet::none();
        self.receive_buf = None;
        self.stage = HandleStage::Destroyed;
    }

    pub fn is_destroyed(&self) -> bool {
        self.stage == HandleStage::Destroyed
    }
}

impl Caller for UdpProcessor {
    fn get_id(&self) -> Token {
        self.token.unwrap()
    }

    fn handle_dns_resolved(&mut self,
                           _event_loop: &mut EventLoop<Relay>,
                           hostname_ip: Option<(String, String)>,
                           errmsg: Option<String>)
                           -> ProcessResult<Vec<Token>> {
        debug!("UDP processor stage: DNS resolved");
        self.stage = HandleStage::DNS;
        if let Some(e) = errmsg {
            error!("UDP processor resolve DNS error: {}", e);
            return self.process_failed();
        }

        if let Some((hostname, ip)) = hostname_ip {
            if !self.requests.contains_key(&hostname) {
                // TODO: add log
                return self.process_failed();
            }

            let port_requests_map = self.requests.remove(&hostname).unwrap();
            for (port, requests) in port_requests_map.iter() {
                let ip_port = format!("{}:{}", ip, port);
                let server_addr = str2addr4(&ip_port).unwrap();

                for request in requests {
                    self.send_to(CLIENT, &request, &server_addr);
                }
            }

            ProcessResult::Success
        } else {
            self.process_failed()
        }
    }
}

const BUF_SIZE: usize = 64 * 1024;
const CLIENT: bool = true;
const SERVER: bool = false;

#[derive(Debug, PartialEq)]
enum HandleStage {
    // only sslocal: auth METHOD received from local, reply with selection message
    Init,
    // DNS resolved, connect to remote
    DNS,
    Stream,
    Destroyed,
}
