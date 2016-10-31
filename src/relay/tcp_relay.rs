use std::rc::Rc;
use std::cell::RefCell;
use std::process::exit;

use mio::tcp::TcpListener;
use mio::{Token, EventSet, EventLoop, PollOpt};

use config::Config;
use network::str2addr4;
use collections::Holder;
use asyncdns::DNSResolver;
use super::{TcpProcessor, MyHandler, Relay, ProcessResult};

type RcCellTcpProcessor = Rc<RefCell<TcpProcessor>>;

pub struct TcpRelay {
    conf: Config,
    listener: TcpListener,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    processors: Holder<RcCellTcpProcessor>,
}

impl TcpRelay {
    pub fn new(conf: Config) -> TcpRelay {
        let address = format!("{}:{}",
                              conf["listen_address"].as_str().unwrap(),
                              conf["listen_port"].as_integer().unwrap());
        // TODO: parse prefer_ipv6 from command line
        let dns_resolver = Rc::new(RefCell::new(DNSResolver::new(None, false)));
        // TODO: need resolve DNS here
        let socket_addr = str2addr4(&address).unwrap_or_else(|| {
            error!("invalid socket address: {}", address);
            exit(1);
        });
        let listener = TcpListener::bind(&socket_addr).unwrap_or_else(|e| {
            error!("tcp relay cannot bind address {} because {}", address, e);
            exit(1);
        });

        if cfg!(feature = "sslocal") {
            info!("ssclient tcp relay listen on {}", address);
        } else {
            info!("ssserver tcp relay listen on {}", address);
        }

        TcpRelay {
            conf: conf,
            listener: listener,
            dns_resolver: dns_resolver,
            processors: Holder::new_exclude_from(vec![RELAY_TOKEN, DNS_RESOLVER_TOKEN]),
        }
    }

    pub fn run(self) {
        let mut event_loop = EventLoop::new().unwrap();

        if let Err(e) = event_loop.register(&self.listener,
                                            RELAY_TOKEN,
                                            EventSet::readable(),
                                            PollOpt::edge() | PollOpt::oneshot()) {
            error!("failed to register tcp relay: {}", e);
            exit(1);
        }
        if !self.dns_resolver.borrow_mut().register(&mut event_loop, DNS_RESOLVER_TOKEN) {
            error!("failed to register dns resolver");
            exit(1);
        }

        let this = Rc::new(RefCell::new(self));
        event_loop.run(&mut Relay::Tcp(this)).unwrap();
    }

    fn add_processor(&mut self, processor: RcCellTcpProcessor) -> Option<Token> {
        self.processors.insert(processor)
    }

    fn remove_processor(&mut self, token: Token) -> Option<RcCellTcpProcessor> {
        self.processors.remove(token)
    }

    fn destroy_processor(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        if !self.processors[token].borrow().is_destroyed() {
            self.processors[token].borrow_mut().destroy(event_loop);
        }
        self.remove_processor(token);
    }

    pub fn process(&mut self,
                   event_loop: &mut EventLoop<Relay>,
                   _token: Token,
                   events: EventSet)
                   -> ProcessResult<Vec<Token>> {
        if let Err(e) = event_loop.reregister(&self.listener,
                                              RELAY_TOKEN,
                                              EventSet::readable(),
                                              PollOpt::edge() | PollOpt::oneshot()) {
            error!("failed to reregister tcp relay: {}", e);
            // TODO: find a more gentle way to handle this
            exit(1);
        }

        if events.is_error() {
            error!("events error on tcp relay: {:?}",
                   self.listener.take_socket_error().unwrap_err());
        } else {
            match self.listener.accept() {
                Ok(Some((conn, _addr))) => {
                    info!("create tcp processor for {}", _addr);
                    let p = TcpProcessor::new(self.conf.clone(), conn, self.dns_resolver.clone());
                    let p = Rc::new(RefCell::new(p));
                    let tokens = (self.add_processor(p.clone()), self.add_processor(p.clone()));

                    // register local socket to event loop
                    if let (Some(local_token), Some(remote_token)) = tokens {
                        p.borrow_mut().set_token(local_token, true);
                        p.borrow_mut().set_token(remote_token, false);
                        self.dns_resolver.borrow_mut().add_caller(p.clone());
                        p.borrow_mut().reset_timeout(event_loop);
                        if !p.borrow_mut().register(event_loop, true) {
                            return ProcessResult::Failed(vec![local_token, remote_token]);
                        }
                    } else {
                        error!("cannot alloc tokens for tcp processor");
                        match tokens {
                            (Some(t), None) => { self.remove_processor(t); }
                            (None, Some(t)) => { self.remove_processor(t); }
                            (Some(t1), Some(t2)) => {
                                self.remove_processor(t1);
                                self.remove_processor(t2);
                            }
                            (None, None) => {}
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => error!("accept tcp connection failed: {}", e),
            }
        }

        ProcessResult::Success
    }

    pub fn destroy(&mut self, _event_loop: &mut EventLoop<Relay>) {
        unimplemented!();
    }

    pub fn is_destroyed(&self) -> bool {
        unimplemented!();
    }
}

impl MyHandler for TcpRelay {
    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        let result = match token {
            RELAY_TOKEN => self.process(event_loop, token, events),
            DNS_RESOLVER_TOKEN => {
                self.dns_resolver.borrow_mut().process(event_loop, token, events);
                ProcessResult::Success
            }
            token => {
                if let Some(processor) = self.processors.get(token) {
                    processor.borrow_mut().process(event_loop, token, events)
                } else {
                    debug!("got events {:?} for destroyed tcp processor {:?}", events, token);
                    return;
                }
            }
        };

        if let ProcessResult::Failed(tokens) = result {
            for token in tokens {
                match token {
                    RELAY_TOKEN => self.destroy(event_loop),
                    DNS_RESOLVER_TOKEN => self.dns_resolver.borrow_mut().destroy(event_loop),
                    _ => self.destroy_processor(event_loop, token),
                }
            }
        }
    }

    fn timeout(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        warn!("tcp processor {:?} timed out", token);
        self.destroy_processor(event_loop, token);
    }
}

const RELAY_TOKEN: Token = Token(0);
const DNS_RESOLVER_TOKEN: Token = Token(1);
