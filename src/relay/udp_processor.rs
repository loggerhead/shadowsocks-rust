use std::rc::Rc;
use std::cell::RefCell;
use std::net::SocketAddr;

use mio::udp::UdpSocket;
use mio::{EventSet, Token, Timeout, EventLoop, PollOpt};

use util::shift_vec;
use socks5::{parse_header, pack_addr};
use encrypt::Encryptor;
use config::Config;
use network::{str2addr4, NetworkWriteBytes};
use asyncdns::{DNSResolver, Caller};
use super::{Relay, ProcessResult};

pub type ProcessorId = (u16, u16, String, String);
const BUF_SIZE: usize = 64 * 1024;

pub struct UdpProcessor {
    conf: Config,
    token: Option<Token>,
    interest: EventSet,
    timeout: Option<Timeout>,
    sock: UdpSocket,
    relay_sock: Rc<RefCell<UdpSocket>>,
    client_sock_addr: SocketAddr,
    server_sock_addr: Option<SocketAddr>,
    client_address: (String, u16),
    server_address: (String, u16),
    local_buf: Option<Vec<u8>>,
    remote_buf: Option<Vec<u8>>,
    unfinished_send_tasks: Rc<RefCell<Vec<(SocketAddr, Vec<u8>)>>>,
    header_length: usize,
    encryptor: Encryptor,
    dns_resolver: Rc<RefCell<DNSResolver>>,
}

impl UdpProcessor {
    pub fn new(conf: Config,
               addr: SocketAddr,
               header_length: usize,
               client_address: (String, u16),
               server_address: (String, u16),
               relay_sock: Rc<RefCell<UdpSocket>>,
               unfinished_send_tasks: Rc<RefCell<Vec<(SocketAddr, Vec<u8>)>>>,
               dns_resolver: Rc<RefCell<DNSResolver>>) -> UdpProcessor {
        let encryptor = Encryptor::new(conf["password"].as_str().unwrap());
        let sock = UdpSocket::v4().unwrap();

        UdpProcessor {
            conf: conf,
            token: None,
            interest: EventSet::readable(),
            timeout: None,
            sock: sock,
            relay_sock: relay_sock,
            client_sock_addr: addr,
            server_sock_addr: None,
            client_address: client_address,
            server_address: server_address,
            local_buf: Some(Vec::with_capacity(BUF_SIZE)),
            remote_buf: None,
            unfinished_send_tasks: unfinished_send_tasks,
            header_length: header_length,
            encryptor: encryptor,
            dns_resolver: dns_resolver,
        }
    }

    pub fn set_token(&mut self, token: Token) {
        self.token = Some(token);
    }

    pub fn processor_id(&self) -> ProcessorId {
        let (caddr, cport) = self.client_address.clone();
        let (saddr, sport) = self.server_address.clone();
        (cport, sport, caddr, saddr)
    }

    fn process_failed(&self) -> ProcessResult<Vec<Token>> {
        ProcessResult::Failed(vec![self.token.unwrap()])
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

    pub fn handle_init(&mut self, event_loop: &mut EventLoop<Relay>, data: &[u8]) -> ProcessResult<Vec<Token>> {
        debug!("UDP processor stage: init");
        // copy data to self.remote_buf
        if self.remote_buf.is_none() {
            self.remote_buf = Some(Vec::with_capacity(data.len()));
        }
        if let Some(ref mut buf) = self.remote_buf {
            if buf.capacity() < data.len() {
                let inc_cap = data.len() - buf.capacity();
                buf.reserve(inc_cap);
            }
            unsafe { buf.set_len(data.len()); }
            buf[..].copy_from_slice(data);
        }

        // resolve server address by async DNS
        let server_addr = self.server_address.0.clone();
        let resolved = self.dns_resolver.borrow_mut().resolve(self.token.unwrap(), server_addr);

        match resolved {
            (None, None) => {}
            // if address is resolved immediately
            (hostname_ip, errmsg) => {
                self.handle_dns_resolved(event_loop, hostname_ip, errmsg);
            }
        }

        ProcessResult::Success
    }

    fn send_to(&self, data: &[u8], is_send_to_client: bool) -> Option<usize> {
        let result = if is_send_to_client {
            debug!("send UDP request to client: {}", self.client_sock_addr);
            self.relay_sock.borrow().send_to(data, &self.client_sock_addr)
        } else {
            debug!("send UDP request to server: {}", self.server_sock_addr.unwrap());
            self.sock.send_to(data, &self.server_sock_addr.unwrap())
        };

        match result {
            Ok(None) => Some(0),
            Ok(Some(n)) => Some(n),
            Err(e) => {
                error!("UDP processor send data failed: {}", e);
                None
            }
        }
    }

    fn on_write(&mut self, _event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        debug!("UDP processor: on_write");
        let mut buf = self.remote_buf.take().unwrap();
        if buf.is_empty() {
            self.remote_buf = Some(buf);
            return ProcessResult::Success;
        }

        if let Some(nwrite) = self.send_to(&buf, SERVER) {
            if nwrite == buf.len() {
                self.interest = EventSet::readable();
            } else {
                self.interest = EventSet::readable() | EventSet::writable();
                shift_vec(&mut buf, nwrite);
            }
        } else {
            return self.process_failed();
        }

        self.remote_buf = Some(buf);
        ProcessResult::Success
    }

    fn on_read(&mut self, _event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        // send to client, append unfinished data to `unfinished_send_tasks`
        macro_rules! try_send {
            ($data:expr) => (
                if let Some(nwrite) = self.send_to(&$data, CLIENT) {
                    if nwrite < $data.len() {
                        shift_vec(&mut $data, nwrite);
                        let task = (self.client_sock_addr.clone(), $data);
                        self.unfinished_send_tasks.borrow_mut().push(task);
                    }
                } else {
                    return self.process_failed();
                }
            )
        }

        debug!("UDP processor: on_read");
        let mut buf = self.local_buf.take().unwrap();
        unsafe { buf.set_len(0); }
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
                            try_send!(response);
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

                    let encrypted = self.encryptor.encrypt_udp(&data);
                    if let Some(mut data) = encrypted {
                        try_send!(data);
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

        self.local_buf = Some(buf);
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

        if events.is_readable() || events.is_hup() {
            try_process!(self.on_read(event_loop));
        }
        if events.is_writable() {
            try_process!(self.on_write(event_loop));
        }

        self.reregister(event_loop);
        ProcessResult::Success
    }

    pub fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        unimplemented!();
    }

    pub fn is_destroyed(&self) -> bool {
        unimplemented!();
    }
}

impl Caller for UdpProcessor {
    fn get_id(&self) -> Token {
        self.token.unwrap()
    }

    fn handle_dns_resolved(&mut self,
                           event_loop: &mut EventLoop<Relay>,
                           hostname_ip: Option<(String, String)>,
                           errmsg: Option<String>)
                           -> ProcessResult<Vec<Token>> {
        debug!("UDP processor stage: DNS resolved");
        if let Some(errmsg) = errmsg {
            error!("UDP processor resolve DNS error: {}", errmsg);
            return self.process_failed();
        }

        match hostname_ip {
            Some((_hostname, ip)) => {
                let ip_port = format!("{}:{}", ip, self.server_address.1);
                self.server_sock_addr = str2addr4(&ip_port);

                let mut unfinished = 0;
                let mut buf = self.remote_buf.take().unwrap();

                if cfg!(feature = "sslocal") {
                    match self.encryptor.encrypt_udp(&buf) {
                        Some(ref data) => {
                            // copy unfinished data to self.remote_buf
                            if let Some(nwrite) = self.send_to(data, SERVER) {
                                unfinished = data.len() - nwrite;
                                unsafe { buf.set_len(0); }
                                if unfinished > 0 {
                                    buf.extend_from_slice(&data[nwrite..]);
                                }
                            } else {
                                return self.process_failed();
                            }
                        }
                        _ => {
                            error!("UDP processor encrypt data failed");
                            return self.process_failed();
                        }
                    }
                } else {
                    // shift unfinished data to self.remote_buf
                    if let Some(nwrite) = self.send_to(&buf[self.header_length..], SERVER) {
                        shift_vec(&mut buf, self.header_length + nwrite);
                    } else {
                        return self.process_failed();
                    }
                }

                self.remote_buf = Some(buf);
                if unfinished > 0 {
                    self.interest = EventSet::readable() | EventSet::writable();
                }
            }
            _ => {
                return self.process_failed();
            }
        }

        ProcessResult::Success
    }
}

const CLIENT: bool = true;
const SERVER: bool = false;
