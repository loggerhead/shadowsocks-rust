use std::io;
use std::io::Result;

use mio::tcp::{TcpListener, TcpStream};
use mio::{Token, EventSet, EventLoop, PollOpt};

use mode::ServerChooser;
use config::Config;
use network::{str2addr4, str2addr6};
use collections::Holder;
use asyncdns::DNSResolver;
use util::{RcCell, new_rc_cell};
use super::{TcpProcessor, MyHandler, Relay};
use super::tcp_processor::LOCAL;

macro_rules! err {
    ($($arg:tt)*) => ( base_err!($($arg)*) );
}

pub struct TcpRelay {
    token: Token,
    conf: Config,
    listener: TcpListener,
    dns_token: Token,
    dns_resolver: RcCell<DNSResolver>,
    server_chooser: RcCell<ServerChooser>,
    processors: Holder<RcCell<TcpProcessor>>,
}

impl TcpRelay {
    pub fn new(conf: Config) -> Result<TcpRelay> {
        let mut processors = Holder::new();
        let token = try!(processors.alloc_token().ok_or(err!(AllocTokenFailed)));
        let dns_token = try!(processors.alloc_token().ok_or(err!(AllocTokenFailed)));

        let prefer_ipv6 = conf["prefer_ipv6"].as_bool().unwrap();
        let mut dns_resolver = try!(DNSResolver::new(dns_token, None, prefer_ipv6));
        let server_chooser = try!(ServerChooser::new(&conf));

        let host = conf["listen_address"].as_str().unwrap().to_string();
        let port = conf["listen_port"].as_integer().unwrap();
        let (_host, ip) = try!(dns_resolver.block_resolve(host)
            .and_then(|h| h.ok_or(err!(DnsResolveFailed, "timeout"))));
        let address = format!("{}:{}", ip, port);

        let socket_addr = try!(if prefer_ipv6 {
                str2addr6(&address)
            } else {
                str2addr4(&address)
            }
            .ok_or(err!(ParseAddrFailed)));
        let listener = try!(TcpListener::bind(&socket_addr).or(Err(err!(BindAddrFailed, address))));


        if cfg!(feature = "sslocal") {
            info!("ssclient tcp relay listen on {}", address);
        } else {
            info!("ssserver tcp relay listen on {}", address);
        }

        Ok(TcpRelay {
            token: token,
            conf: conf,
            listener: listener,
            dns_token: dns_token,
            dns_resolver: new_rc_cell(dns_resolver),
            server_chooser: new_rc_cell(server_chooser),
            processors: processors,
        })
    }

    pub fn run(self) -> Result<()> {
        let mut event_loop = try!(EventLoop::new());
        try!(event_loop.register(&self.listener,
                      self.token,
                      EventSet::readable(),
                      PollOpt::edge() | PollOpt::oneshot())
            .or(Err(err!(RegisterFailed))));
        try!(self.dns_resolver
            .borrow_mut()
            .register(&mut event_loop)
            .or(Err(err!(RegisterFailed))));
        let this = new_rc_cell(self);
        try!(event_loop.run(&mut Relay::Tcp(this)));
        Ok(())
    }

    fn destroy_processor(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        let tokens = self.processors[token].borrow_mut().destroy(event_loop);
        self.processors.remove(tokens.0);
        self.processors.remove(tokens.1);
    }

    fn create_processor(&mut self,
                        event_loop: &mut EventLoop<Relay>,
                        local_token: Token,
                        remote_token: Token,
                        conn: TcpStream)
                        -> Result<()> {
        let p = try!(TcpProcessor::new(local_token,
                                       remote_token,
                                       self.conf.clone(),
                                       conn,
                                       self.dns_resolver.clone(),
                                       self.server_chooser.clone()));
        let p = new_rc_cell(p);
        self.processors.insert_with(local_token, p.clone());
        self.processors.insert_with(remote_token, p.clone());

        p.borrow_mut().reset_timeout(event_loop);
        self.dns_resolver.borrow_mut().add_caller(p.clone());
        let res = p.borrow_mut().register(event_loop, LOCAL);
        match res {
            Err(e) => {
                self.destroy_processor(event_loop, local_token);
                Err(e)
            }
            res => res,
        }
    }

    fn process(&mut self, event_loop: &mut EventLoop<Relay>, events: EventSet) -> Result<()> {
        try!(event_loop.reregister(&self.listener,
                                   self.token,
                                   EventSet::readable(),
                                   PollOpt::edge() | PollOpt::oneshot()));
        if events.is_error() {
            error!("events error on tcp relay: {:?}",
                   self.listener.take_socket_error().unwrap_err());
            return Err(err!(EventError));
        }

        match try!(self.listener.accept()) {
            Some((conn, _addr)) => {
                debug!("create tcp processor for {}", _addr);
                let tokens = (self.processors.alloc_token(), self.processors.alloc_token());
                if let (Some(local_token), Some(remote_token)) = tokens {
                    self.create_processor(event_loop, local_token, remote_token, conn)
                } else {
                    match tokens {
                        (None, None) => {}
                        (Some(t), None) | (None, Some(t)) => {
                            self.processors.remove(t);
                        }
                        (Some(t1), Some(t2)) => {
                            self.processors.remove(t1);
                            self.processors.remove(t2);
                        }
                    }
                    Err(err!(AllocTokenFailed))
                }
            }
            None => Ok(()),
        }
    }
}

impl MyHandler for TcpRelay {
    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        if token == self.token {
            self.process(event_loop, events)
                .map_err(|e| {
                    error!("tcp relay: {}", e);
                })
                .unwrap();
        } else if token == self.dns_token {
            self.dns_resolver
                .borrow_mut()
                .process(event_loop, events)
                .map_err(|e| {
                    error!("dns resolver: {}", e);
                })
                .unwrap();
        } else {
            let res = self.processors.get(token).map(|p| {
                try!(p.borrow().fetch_error());
                p.borrow_mut().process(event_loop, token, events)
            });
            if let Some(Err(e)) = res {
                if e.kind() != io::ErrorKind::ConnectionReset {
                    error!("{:?}: {}",
                           &self.processors[token].borrow() as &TcpProcessor,
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
