use std::rc::Rc;
use std::cell::RefCell;
use std::process::exit;
use std::net::SocketAddr;

use mio::tcp::TcpListener;
use mio::{Token, Handler, EventSet, EventLoop, PollOpt};

use util::Holder;
use config::Config;
use network::str2addr4;
use asyncdns::DNSResolver;
use tcp_processor::TCPProcessor;

const RELAY_TOKEN: Token = Token(0);
const DNS_RESOLVER_TOKEN: Token = Token(1);

#[derive(Debug, PartialEq)]
pub enum ProcessResult<T> {
    Success,
    Failed(T),
}

#[allow(unused_variables)]
pub trait Processor {
    fn process(&mut self,
               event_loop: &mut EventLoop<Relay>,
               token: Token,
               events: EventSet)
               -> ProcessResult<Vec<Token>>;

    fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        unimplemented!();
    }

    fn is_destroyed(&self) -> bool {
        unimplemented!();
    }
}

pub struct Relay {
    conf: Config,
    tcp_listener: TcpListener,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    processors: Holder<Rc<RefCell<Processor>>>,
}

impl Relay {
    pub fn new(conf: Config) -> Relay {
        let address = format!("{}:{}",
                              conf["listen_address"].as_str().unwrap(),
                              conf["listen_port"].as_integer().unwrap());
        let dns_resolver = Rc::new(RefCell::new(DNSResolver::new(None, None)));
        let socket_addr = str2addr4(&address).unwrap_or_else(|| {
            error!("invalid socket address: {}", address);
            exit(1);
        });
        let tcp_listener = TcpListener::bind(&SocketAddr::V4(socket_addr)).unwrap_or_else(|e| {
            error!("cannot bind address {} because {}", address, e);
            exit(1);
        });
        if cfg!(feature = "is_client") {
            info!("ssclient listen on {}", address);
        } else {
            info!("ssserver listen on {}", address);
        }

        Relay {
            conf: conf,
            tcp_listener: tcp_listener,
            dns_resolver: dns_resolver,
            processors: Holder::new_exclude_from(vec![RELAY_TOKEN, DNS_RESOLVER_TOKEN]),
        }
    }

    pub fn add_processor(&mut self, processor: Rc<RefCell<Processor>>) -> Option<Token> {
        self.processors.add(processor)
    }

    pub fn remove_processor(&mut self, token: Token) -> Option<Rc<RefCell<Processor>>> {
        self.processors.del(token)
    }

    pub fn run(&mut self) {
        let mut event_loop = EventLoop::new().unwrap();

        if let Err(e) = event_loop.register(&self.tcp_listener,
                                            RELAY_TOKEN,
                                            EventSet::readable(),
                                            PollOpt::edge() | PollOpt::oneshot()) {
            error!("failed to register relay: {}", e);
            exit(1);
        }
        if !self.dns_resolver.borrow_mut().register(&mut event_loop, DNS_RESOLVER_TOKEN) {
            error!("failed to register DNS resolver");
            exit(1);
        }

        event_loop.run(self).unwrap();
    }
}

impl Handler for Relay {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        let result = match token {
            RELAY_TOKEN => self.process(event_loop, token, events),
            DNS_RESOLVER_TOKEN => self.dns_resolver.borrow_mut().process(event_loop, token, events),
            token @ Token(_) => {
                let processor = self.processors.get(token);
                match processor {
                    Some(processor) => processor.borrow_mut().process(event_loop, token, events),
                    _ => {
                        debug!("got events {:?} for destroyed processor {:?}",
                               events,
                               token);
                        return;
                    }
                }

            }
        };

        match result {
            ProcessResult::Success => {}
            ProcessResult::Failed(tokens) => {
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
    }
}

impl Processor for Relay {
    fn process(&mut self,
               event_loop: &mut EventLoop<Relay>,
               _token: Token,
               events: EventSet)
               -> ProcessResult<Vec<Token>> {
        let mut result = ProcessResult::Success;

        if events.is_error() {
            error!("events error on relay: {:?}",
                   self.tcp_listener.take_socket_error().unwrap_err());
        } else {
            match self.tcp_listener.accept() {
                Ok(Some((conn, _addr))) => {
                    info!("create processor for {}", _addr);
                    let tcp_processor =
                        TCPProcessor::new(self.conf.clone(), conn, self.dns_resolver.clone());
                    let tcp_processor = Rc::new(RefCell::new(tcp_processor));
                    let tokens = (self.add_processor(tcp_processor.clone()),
                                  self.add_processor(tcp_processor.clone()));

                    // register local socket to event loop
                    match tokens {
                        (Some(local_token), Some(remote_token)) => {
                            tcp_processor.borrow_mut().set_local_token(local_token);
                            tcp_processor.borrow_mut().set_remote_token(remote_token);
                            self.dns_resolver.borrow_mut().add_caller(tcp_processor.clone());
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

        if let Err(e) = event_loop.reregister(&self.tcp_listener,
                                              RELAY_TOKEN,
                                              EventSet::readable(),
                                              PollOpt::edge() | PollOpt::oneshot()) {
            error!("failed to reregister relay: {}", e);
            exit(1);
        }

        result
    }
}