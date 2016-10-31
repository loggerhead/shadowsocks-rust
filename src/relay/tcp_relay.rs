use std::io;
use std::io::Result;

use mio::tcp::TcpListener;
use mio::{Token, EventSet, EventLoop, PollOpt};

use config::Config;
use network::str2addr4;
use collections::Holder;
use asyncdns::DNSResolver;
use util::{RcCell, new_rc_cell};
use super::{TcpProcessor, MyHandler, Relay, RELAY_TOKEN, DNS_RESOLVER_TOKEN};
use super::tcp_processor::{LOCAL, REMOTE};

macro_rules! err {
    ($($arg:tt)*) => ( base_err!($($arg)*) );
}

pub struct TcpRelay {
    conf: Config,
    listener: TcpListener,
    dns_resolver: RcCell<DNSResolver>,
    processors: Holder<RcCell<TcpProcessor>>,
}

impl TcpRelay {
    pub fn new(conf: Config) -> Result<TcpRelay> {
        // TODO: need resolve DNS here
        // TODO: parse prefer_ipv6 from command line
        let address = format!("{}:{}",
                              conf["listen_address"].as_str().unwrap(),
                              conf["listen_port"].as_integer().unwrap());
        let dns_resolver = new_rc_cell(try!(DNSResolver::new(None, false)));
        let socket_addr = try!(str2addr4(&address).ok_or(err!(ParseAddrFailed)));
        let listener = try!(TcpListener::bind(&socket_addr).or(Err(err!(BindAddrFailed, address))));

        if cfg!(feature = "sslocal") {
            info!("ssclient tcp relay listen on {}", address);
        } else {
            info!("ssserver tcp relay listen on {}", address);
        }

        Ok(TcpRelay {
            conf: conf,
            listener: listener,
            dns_resolver: dns_resolver,
            processors: Holder::new_exclude_from(vec![RELAY_TOKEN, DNS_RESOLVER_TOKEN]),
        })
    }

    pub fn run(self) -> Result<()> {
        let mut event_loop = try!(EventLoop::new());
        try!(event_loop.register(&self.listener,
                                 RELAY_TOKEN,
                                 EventSet::readable(),
                                 PollOpt::edge() | PollOpt::oneshot())
                       .or(Err(err!(RegisterFailed))));
        try!(self.dns_resolver.borrow_mut().register(&mut event_loop, DNS_RESOLVER_TOKEN)
                                           .or(Err(err!(RegisterFailed))));
        let this = new_rc_cell(self);
        try!(event_loop.run(&mut Relay::Tcp(this)));
        Ok(())
    }

    fn add_processor(&mut self, processor: RcCell<TcpProcessor>) -> Option<Token> {
        self.processors.insert(processor)
    }

    fn remove_processor(&mut self, token: Token) -> Option<RcCell<TcpProcessor>> {
        self.processors.remove(token)
    }

    fn remove_tokens(&mut self, tokens: (Option<Token>, Option<Token>)) {
        match tokens {
            (None, None) => {},
            (Some(t), None) | (None, Some(t)) => {
                self.remove_processor(t);
            }
            (Some(t1), Some(t2)) => {
                self.remove_processor(t1);
                self.remove_processor(t2);
            }
        }
    }

    fn destroy_processor(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        let tokens = self.processors[token].borrow_mut().destroy(event_loop);
        self.remove_tokens(tokens);
    }

    fn process(&mut self,
               event_loop: &mut EventLoop<Relay>,
               _token: Token,
               events: EventSet)
               -> Result<()> {
        try!(event_loop.reregister(&self.listener,
                                   RELAY_TOKEN,
                                   EventSet::readable(),
                                   PollOpt::edge() | PollOpt::oneshot()));
        if events.is_error() {
            error!("events error on tcp relay: {:?}",
                   self.listener.take_socket_error().unwrap_err());
            return Err(err!(EventError));
        }

        let client = try!(self.listener.accept());
        if let Some((conn, _addr)) = client {
            debug!("create tcp processor for {}", _addr);
            let p = try!(TcpProcessor::new(self.conf.clone(), conn, self.dns_resolver.clone()));
            let p = new_rc_cell(p);
            let tokens = (self.add_processor(p.clone()), self.add_processor(p.clone()));

            // register local socket to event loop
            if let (Some(local_token), Some(remote_token)) = tokens {
                p.borrow_mut().set_token(local_token, LOCAL);
                p.borrow_mut().set_token(remote_token, REMOTE);
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
            } else {
                self.remove_tokens(tokens);
                Err(err!(AllocTokenFailed))
            }
        } else {
            Ok(())
        }
    }
}

impl MyHandler for TcpRelay {
    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        match token {
            RELAY_TOKEN => {
                self.process(event_loop, token, events).map_err(|e| {
                    error!("tcp relay: {}", e);
                }).unwrap();
            }
            DNS_RESOLVER_TOKEN => {
                self.dns_resolver.borrow_mut().process(event_loop, token, events).map_err(|e| {
                    error!("dns resolver: {}", e);
                }).unwrap();
            }
            token => {
                let res = self.processors.get(token).map(|p| {
                    try!(p.borrow().fetch_error());
                    p.borrow_mut().process(event_loop, token, events)
                });
                if let Some(Err(e)) = res {
                    if e.kind() != io::ErrorKind::ConnectionReset {
                        error!("{:?}: {}", &self.processors[token].borrow() as &TcpProcessor, e);
                    }
                    self.destroy_processor(event_loop, token);
                }
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
