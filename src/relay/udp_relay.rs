// SOCKS5 UDP Request/Response
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

// shadowsocks UDP Request/Response (before encrypted)
// +------+----------+----------+----------+
// | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +------+----------+----------+----------+
// |  1   | Variable |    2     | Variable |
// +------+----------+----------+----------+

// shadowsocks UDP Request/Response (after encrypted)
// +-------+--------------+
// |   IV  |    PAYLOAD   |
// +-------+--------------+
// | Fixed |   Variable   |
// +-------+--------------+
use std::rc::Rc;
use std::cell::RefCell;
use std::process::exit;
use std::net::SocketAddr;

use mio::udp::UdpSocket;
use mio::{Token, EventSet, EventLoop, PollOpt};

use socks5::parse_header;
use encrypt::Encryptor;
use util::shift_vec;
use config::Config;
use network::str2addr4;
use collections::{Holder, Dict};
use asyncdns::DNSResolver;
use super::{choose_a_server, Relay, MyHandler, UdpProcessor, ProcessResult};
use super::udp_processor::ProcessorId;

const BUF_SIZE: usize = 64 * 1024;
const RELAY_TOKEN: Token = Token(0);
const DNS_RESOLVER_TOKEN: Token = Token(1);

type RcCellUdpProcessor = Rc<RefCell<UdpProcessor>>;

pub struct UdpRelay {
    conf: Config,
    interest: EventSet,
    listener: Rc<RefCell<UdpSocket>>,
    receive_buf: Option<Vec<u8>>,
    unfinished_send_tasks: Rc<RefCell<Vec<(SocketAddr, Vec<u8>)>>>,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    id_processor_map: Dict<ProcessorId, RcCellUdpProcessor>,
    processors: Holder<RcCellUdpProcessor>,
    encryptor: Encryptor,
}

impl UdpRelay {
    pub fn new(conf: Config) -> UdpRelay {
        let address = format!("{}:{}",
                              conf["listen_address"].as_str().unwrap(),
                              conf["listen_port"].as_integer().unwrap());
        let dns_resolver = Rc::new(RefCell::new(DNSResolver::new(None, false)));
        let client_addr = str2addr4(&address).unwrap_or_else(|| {
            error!("invalid socket address: {}", address);
            exit(1);
        });

        let listener = UdpSocket::v4().and_then(|sock| {
            try!(sock.bind(&client_addr));
            Ok(sock)
        }).unwrap_or_else(|e| {
            error!("cannot bind address {} because {}", address, e);
            exit(1);
        });
        let encryptor = Encryptor::new(conf["password"].as_str().unwrap());

        if cfg!(feature = "sslocal") {
            info!("ssclient udp relay listen on {}", address);
        } else {
            info!("ssserver udp relay listen on {}", address);
        }

        UdpRelay {
            conf: conf,
            interest: EventSet::readable(),
            receive_buf: Some(Vec::with_capacity(BUF_SIZE)),
            listener: Rc::new(RefCell::new(listener)),
            unfinished_send_tasks: Rc::new(RefCell::new(Vec::new())),
            dns_resolver: dns_resolver,
            id_processor_map: Dict::new(),
            processors: Holder::new_exclude_from(vec![RELAY_TOKEN, DNS_RESOLVER_TOKEN]),
            encryptor: encryptor,
        }
    }

    pub fn run(self) {
        let mut event_loop = EventLoop::new().unwrap();

        if let Err(e) = event_loop.register(&*self.listener.borrow(),
                                            RELAY_TOKEN,
                                            self.interest,
                                            PollOpt::edge() | PollOpt::oneshot()) {
            error!("failed to register udp relay: {}", e);
            exit(1);
        }
        if !self.dns_resolver.borrow_mut().register(&mut event_loop, DNS_RESOLVER_TOKEN) {
            error!("failed to register DNS resolver");
            exit(1);
        }

        let this = Rc::new(RefCell::new(self));
        event_loop.run(&mut Relay::Udp(this)).unwrap();
    }

    fn add_processor(&mut self, processor: RcCellUdpProcessor) -> Option<Token> {
        self.processors.add(processor)
    }

    fn remove_processor(&mut self, token: Token) -> Option<RcCellUdpProcessor> {
        let p = try_opt!(self.processors.del(token));
        let res = self.id_processor_map.del(&p.borrow().processor_id());
        res
    }

    fn on_read(&mut self, event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        let mut buf = self.receive_buf.take().unwrap();
        new_fat_slice_from_vec!(buf_slice, buf);

        let result = self.listener.borrow().recv_from(buf_slice);
        match result {
            Ok(None) => { }
            Ok(Some((n, addr))) => {
                debug!("receive UDP request from {}", addr);
                unsafe { buf.set_len(n); }
                if buf.len() < 3 {
                    warn!("UDP handshake header too short");
                } else {
                    if cfg!(feature = "sslocal") {
                        if buf[2] == 0 {
                            // skip REV and FRAG fields
                            self.handle_local_side(event_loop, addr, &buf[3..]);
                        } else {
                            warn!("UDP drop a message since frag is not 0");
                        }
                    } else {
                        let decrypted = self.encryptor.decrypt_udp(&buf);
                        if let Some(data) = decrypted {
                            self.handle_local_side(event_loop, addr, &data);
                        } else {
                            warn!("decrypt udp data failed");
                        }
                    }
                }
            }
            Err(e) => error!("udp relay receive data failed: {}", e),
        }

        self.receive_buf = Some(buf);
        ProcessResult::Success
    }

    fn on_write(&mut self, _event_loop: &mut EventLoop<Relay>) -> ProcessResult<Vec<Token>> {
        debug!("UDP relay: on_write");
        let len = self.unfinished_send_tasks.borrow().len();
        let mut unfinished = Vec::with_capacity(len);

        while let Some((addr, mut data)) = self.unfinished_send_tasks.borrow_mut().pop() {
            match self.listener.borrow().send_to(&data, &addr) {
                Ok(None) => {
                    unfinished.push((addr, data));
                }
                Ok(Some(n)) => {
                    shift_vec(&mut data, n);
                    unfinished.push((addr, data));
                }
                Err(e) => {
                    error!("send task failed: {}", e);
                }
            }
        }

        while let Some(addr_and_data) = unfinished.pop() {
            self.unfinished_send_tasks.borrow_mut().push(addr_and_data);
        }

        ProcessResult::Success
    }

    fn process(&mut self,
               event_loop: &mut EventLoop<Relay>,
               _token: Token,
               events: EventSet)
               -> ProcessResult<Vec<Token>> {
        if let Err(e) = event_loop.reregister(&*self.listener.borrow(),
                                              RELAY_TOKEN,
                                              self.interest,
                                              PollOpt::edge() | PollOpt::oneshot()) {
            error!("failed to reregister relay: {}", e);
            // TODO: replace this
            exit(1);
        }

        if events.is_error() {
            // TODO: handle this error
            error!("events error on udp relay");
        } else {
            if events.is_readable() || events.is_hup() {
                try_process!(self.on_read(event_loop));
            }
            if events.is_writable() {
                try_process!(self.on_write(event_loop));
            }
        }

        ProcessResult::Success
    }

    pub fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        unimplemented!();
    }

    pub fn is_destroyed(&self) -> bool {
        unimplemented!();
    }

    // handle data from client or sslocal
    fn handle_local_side(&mut self,
                         event_loop: &mut EventLoop<Relay>,
                         client_sock_addr: SocketAddr,
                         data: &[u8]) -> ProcessResult<Vec<Token>> {
        // parse socks5 header
        if let Some((_addr_type, mut server_addr, mut server_port, header_length)) = parse_header(data) {
            debug!("the destination of current socks5 request is: {}:{}", server_addr, server_port);
            if cfg!(feature = "sslocal") {
                let (addr, port) = choose_a_server(&self.conf).unwrap();
                server_addr = addr;
                server_port = port;
            }

            let client_addr = format!("{}", client_sock_addr.ip());
            let client_port = client_sock_addr.port();
            let processor_id = (client_port, server_port, client_addr.clone(), server_addr.clone());

            // if cached
            if self.id_processor_map.has(&processor_id) {
                debug!("UDP processor {:?} is cached", processor_id);
                let p = &self.id_processor_map[&processor_id];
                p.borrow_mut().handle_init(event_loop, data);
            } else {
                let p = Rc::new(RefCell::new(UdpProcessor::new(self.conf.clone(),
                                                               client_sock_addr,
                                                               header_length,
                                                               (client_addr, client_port),
                                                               (server_addr, server_port),
                                                               self.listener.clone(),
                                                               self.unfinished_send_tasks.clone(),
                                                               self.dns_resolver.clone())));
                if let Some(token) = self.add_processor(p.clone()) {
                    debug!("create a new UDP processor {:?}", processor_id);
                    self.id_processor_map.put(processor_id, p.clone());
                    p.borrow_mut().set_token(token);
                    p.borrow_mut().register(event_loop);
                    p.borrow_mut().handle_init(event_loop, data);
                } else {
                    // TODO: handle error
                    error!("cannot alloc token for udp processor");
                }
            }
        } else {
            // TODO: handle error
            error!("can not parse socks header");
        }

        ProcessResult::Success
    }

}

impl MyHandler for UdpRelay {
    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        let result = match token {
            RELAY_TOKEN => self.process(event_loop, token, events),
            DNS_RESOLVER_TOKEN => {
                // TODO: handle error
                self.dns_resolver.borrow_mut().process(event_loop, token, events);
                ProcessResult::Success
            }
            token => {
                let processor = self.processors.get(token);
                match processor {
                    Some(processor) => {
                        let res = processor.borrow_mut().process(event_loop, token, events);
                        if self.unfinished_send_tasks.borrow().len() > 0 {
                            self.interest = EventSet::writable() | EventSet::readable();
                        }
                        res
                    }
                    _ => {
                        debug!("got events {:?} for destroyed processor {:?}", events, token);
                        return;
                    }
                }
            }
        };

        if let ProcessResult::Failed(tokens) = result {
            for token in tokens {
                match token {
                    // TODO: handle error
                    RELAY_TOKEN => self.destroy(event_loop),
                    DNS_RESOLVER_TOKEN => self.dns_resolver.borrow_mut().destroy(event_loop),
                    _ => {
                        if !self.processors[token].borrow().is_destroyed() {
                            self.processors[token].borrow_mut().destroy(event_loop);
                        }
                        self.remove_processor(token);
                    }
                }
            }
        }
    }

    // TODO: finish timeout
    fn timeout(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        // warn!("{:?} timed out", token);
        // if !self.processors[token].borrow().is_destroyed() {
        //     self.processors[token].borrow_mut().destroy(event_loop);
        // }
    }
}
