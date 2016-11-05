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
use std::io;
use std::io::Result;
use std::net::SocketAddr;

use mio::udp::UdpSocket;
use mio::{Token, EventSet, EventLoop, PollOpt};

use mode::ServerChooser;
use util::{RcCell, new_rc_cell};
use config::Config;
use socks5::parse_header;
use encrypt::Encryptor;
// TODO: rename `DNSResolver` to `DnsResolver`
use asyncdns::DNSResolver;
use collections::{Holder, Dict};
use super::{init_relay, Relay, MyHandler, UdpProcessor};

macro_rules! err {
    (InvalidSocks5Header) => ( io_err!("invalid socks5 header") );
    (Socks5Header) => ( io_err!("invalid socks5 header") );

    ($($arg:tt)*) => ( processor_err!($($arg)*) );
}

// only receive data from client/sslocal,
// and relay the data to `UdpProcessor`
pub struct UdpRelay {
    token: Token,
    conf: Config,
    interest: EventSet,
    listener: RcCell<UdpSocket>,
    receive_buf: Option<Vec<u8>>,
    dns_token: Token,
    dns_resolver: RcCell<DNSResolver>,
    server_chooser: RcCell<ServerChooser>,
    cache: Dict<SocketAddr, RcCell<UdpProcessor>>,
    processors: Holder<RcCell<UdpProcessor>>,
    encryptor: RcCell<Encryptor>,
}

impl UdpRelay {
    pub fn new(conf: Config) -> Result<UdpRelay> {
        init_relay(conf, |conf,
                    token,
                    dns_token,
                    dns_resolver,
                    server_chooser,
                    processors,
                    socket_addr| {
            let encryptor = new_rc_cell(Encryptor::new(conf["password"].as_str().unwrap()));
            let address = format!("{}:{}", socket_addr.ip(), socket_addr.port());
            let listener = try!(UdpSocket::v4()
                .and_then(|sock| {
                    try!(sock.bind(&socket_addr));
                    Ok(sock)
                })
                .or(Err(err!(BindAddrFailed, address))));

            if cfg!(feature = "sslocal") {
                info!("ssclient udp relay listen on {}", address);
            } else {
                info!("ssserver udp relay listen on {}", address);
            }

            Ok(UdpRelay {
                token: token,
                conf: conf,
                interest: EventSet::readable(),
                receive_buf: Some(Vec::with_capacity(BUF_SIZE)),
                listener: new_rc_cell(listener),
                dns_token: dns_token,
                dns_resolver: dns_resolver,
                server_chooser: server_chooser,
                cache: Dict::default(),
                processors: processors,
                encryptor: encryptor,
            })
        })
    }

    pub fn run(self) -> Result<()> {
        let mut event_loop = try!(EventLoop::new());
        try!(event_loop.register(&*self.listener.borrow(),
                      self.token,
                      self.interest,
                      PollOpt::edge() | PollOpt::oneshot())
            .or(Err(err!(RegisterFailed))));
        try!(self.dns_resolver
            .borrow_mut()
            .register(&mut event_loop)
            .or(Err(err!(RegisterFailed))));

        let this = new_rc_cell(self);
        try!(event_loop.run(&mut Relay::Udp(this)));
        Ok(())
    }

    fn remove_processor(&mut self, token: Token) -> Option<RcCell<UdpProcessor>> {
        let p = try_opt!(self.processors.remove(token));
        let res = self.cache.remove(p.borrow().addr());
        res
    }

    fn destroy_processor(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        self.processors[token].borrow_mut().destroy(event_loop);
        self.remove_processor(token);
    }

    fn create_processor(&mut self,
                        event_loop: &mut EventLoop<Relay>,
                        token: Token,
                        client_addr: SocketAddr)
                        -> Result<()> {
        let p = new_rc_cell(try!(UdpProcessor::new(token,
                                                   self.conf.clone(),
                                                   client_addr,
                                                   self.listener.clone(),
                                                   self.dns_resolver.clone(),
                                                   self.server_chooser.clone(),
                                                   self.encryptor.clone())));
        self.processors.insert_with(token, p.clone());
        self.cache.insert(client_addr, p.clone());
        self.dns_resolver.borrow_mut().add_caller(p.clone());
        let res = p.borrow_mut().register(event_loop).map_err(|e| {
            self.destroy_processor(event_loop, token);
            e
        });
        res
    }

    // handle data from client or sslocal
    fn handle_request(&mut self,
                      event_loop: &mut EventLoop<Relay>,
                      client_addr: SocketAddr,
                      data: &[u8])
                      -> Result<()> {
        // parse socks5 header
        match parse_header(data) {
            Some(header) => {
                if !self.cache.contains_key(&client_addr) {
                    debug!("create udp processor for {:?}", client_addr);
                    let token = try!(self.processors.alloc_token().ok_or(err!(AllocTokenFailed)));
                    try!(self.create_processor(event_loop, token, client_addr));
                }

                if data.len() > 0 {
                    let p = &self.cache[&client_addr];
                    try!(p.borrow_mut().handle_request(event_loop, data, header));
                }
                Ok(())
            }
            None => Err(err!(InvalidSocks5Header)),
        }
    }

    fn handle_events(&mut self, event_loop: &mut EventLoop<Relay>, events: EventSet) -> Result<()> {
        try!(event_loop.reregister(&*self.listener.borrow(),
                                   self.token,
                                   self.interest,
                                   PollOpt::edge() | PollOpt::oneshot()));
        if events.is_error() {
            error!("events error on udp relay");
            return Err(err!(EventError));
        }

        let mut buf = self.receive_buf.take().unwrap();
        new_fat_slice_from_vec!(buf_slice, buf);

        let mut res = Ok(());
        let result = self.listener.borrow().recv_from(buf_slice);
        match result {
            Ok(None) => {}
            Ok(Some((nwrite, addr))) => {
                debug!("received udp request from {}", addr);
                if nwrite < 3 {
                    warn!("handshake header of udp request is too short");
                } else {
                    unsafe {
                        buf.set_len(nwrite);
                    }
                    if cfg!(feature = "sslocal") {
                        if buf[2] == 0 {
                            // skip REV and FRAG fields
                            res = self.handle_request(event_loop, addr, &buf[3..]);
                        } else {
                            warn!("drop the udp request since FRAG is not 0");
                        }
                    } else {
                        let decrypted = self.encryptor.borrow_mut().decrypt_udp(&buf);
                        match decrypted {
                            Some(data) => {
                                res = self.handle_request(event_loop, addr, &data);
                            }
                            None => {
                                res = Err(err!(DecryptFailed));
                            }
                        }
                    }
                }
            }
            Err(e) => error!("udp relay receive data failed: {}", e),
        }

        self.receive_buf = Some(buf);
        res
    }
}

impl MyHandler for UdpRelay {
    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        if token == self.token {
            self.handle_events(event_loop, events)
                .map_err(|e| {
                    error!("udp relay: {}", e);
                })
                .unwrap();
        } else if token == self.dns_token {
            self.dns_resolver
                .borrow_mut()
                .handle_events(event_loop, events)
                .map_err(|e| {
                    error!("dns resolver: {}", e);
                })
                .unwrap();
        } else {
            let res = self.processors
                .get(token)
                .map(|p| p.borrow_mut().handle_events(event_loop, token, events));
            if let Some(Err(e)) = res {
                if e.kind() != io::ErrorKind::ConnectionReset {
                    error!("{:?}: {}",
                           &self.processors[token].borrow() as &UdpProcessor,
                           e);
                }
                self.destroy_processor(event_loop, token);
            }
        }
    }

    fn timeout(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        self.processors.get(token).map(|p| {
            debug!("{:?} timed out", p);
        });
        self.destroy_processor(event_loop, token);
    }
}

const BUF_SIZE: usize = 64 * 1024;
