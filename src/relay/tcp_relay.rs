use std::rc::Rc;
use std::cell::RefCell;
use std::process::exit;

use mio::tcp::TcpListener;
use mio::{Token, EventSet, EventLoop, PollOpt};

use config::Config;
use network::str2addr4;
use collections::Holder;
use asyncdns::DNSResolver;
use super::{TCPProcessor, MyHandler, Relay, ProcessResult};

const RELAY_TOKEN: Token = Token(0);
const DNS_RESOLVER_TOKEN: Token = Token(1);

type RcCellTcpProcessor = Rc<RefCell<TCPProcessor>>;

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
            error!("cannot bind address {} because {}", address, e);
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
            error!("failed to register DNS resolver");
            exit(1);
        }

        let this = Rc::new(RefCell::new(self));
        event_loop.run(&mut Relay::Tcp(this)).unwrap();
    }

    fn add_processor(&mut self, processor: RcCellTcpProcessor) -> Option<Token> {
        self.processors.add(processor)
    }

    fn remove_processor(&mut self, token: Token) -> Option<RcCellTcpProcessor> {
        self.processors.del(token)
    }

    pub fn process(&mut self,
                   event_loop: &mut EventLoop<Relay>,
                   _token: Token,
                   events: EventSet)
                   -> ProcessResult<Vec<Token>> {
        let mut result = ProcessResult::Success;

        if events.is_error() {
            error!("events error on relay: {:?}",
                   self.listener.take_socket_error().unwrap_err());
        } else {
            match self.listener.accept() {
                Ok(Some((conn, _addr))) => {
                    info!("create processor for {}", _addr);
                    let tcp_processor = TCPProcessor::new(self.conf.clone(), conn, self.dns_resolver.clone());
                    let tcp_processor = Rc::new(RefCell::new(tcp_processor));
                    let tokens = (self.add_processor(tcp_processor.clone()),
                                  self.add_processor(tcp_processor.clone()));

                    // register local socket to event loop
                    match tokens {
                        (Some(local_token), Some(remote_token)) => {
                            tcp_processor.borrow_mut().set_token(local_token, true);
                            tcp_processor.borrow_mut().set_token(remote_token, false);
                            self.dns_resolver.borrow_mut().add_caller(tcp_processor.clone());
                            tcp_processor.borrow_mut().reset_timeout(event_loop);
                            if !tcp_processor.borrow_mut().register(event_loop, true) {
                                result = ProcessResult::Failed(vec![local_token, remote_token]);
                            }
                        }
                        _ => {
                            error!("cannot generate tokens for TCP processor");
                            let mut tmp = vec![];
                            if let Some(token) = tokens.0 {
                                tmp.push(token);
                            }
                            if let Some(token) = tokens.1 {
                                tmp.push(token);
                            }
                            result = ProcessResult::Failed(tmp);
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => error!("accept TCP connection failed: {}", e),
            }
        }

        if let Err(e) = event_loop.reregister(&self.listener,
                                              RELAY_TOKEN,
                                              EventSet::readable(),
                                              PollOpt::edge() | PollOpt::oneshot()) {
            error!("failed to reregister relay: {}", e);
            // TODO: replace this
            exit(1);
        }

        result
    }

    pub fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
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
                let processor = self.processors.get(token);
                match processor {
                    Some(processor) => processor.borrow_mut().process(event_loop, token, events),
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

    fn timeout(&mut self, event_loop: &mut EventLoop<Relay>, token: Token) {
        warn!("{:?} timed out", token);
        if !self.processors[token].borrow().is_destroyed() {
            self.processors[token].borrow_mut().destroy(event_loop);
        }
    }
}
