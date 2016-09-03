use std::rc::Rc;
use std::cell::RefCell;
use std::net::{SocketAddr};

use mio::{Token, Handler, EventSet, EventLoop, PollOpt};
use mio::tcp::{TcpListener};
use toml::Table;

use config;
use network::str2addr4;
use asyncdns::DNSResolver;
use util::{get_basic_events, Holder};
use tcp_processor::TCPProcessor;


const RELAY_TOKEN: Token = Token(0);
const DNS_RESOLVER_TOKEN: Token = Token(1);

#[derive(Debug, PartialEq)]
pub enum ProcessResult<T> {
    Success,
    Failed(T),
}


pub trait Processor {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) -> ProcessResult<Vec<Token>>;
    fn destroy(&mut self, event_loop: &mut EventLoop<Relay>);
    fn is_destroyed(&self) -> bool;
}


pub struct Relay {
    is_client: bool,
    conf: Rc<Table>,
    tcp_listener: TcpListener,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    processors: Holder<Rc<RefCell<Processor>>>,
}


impl Relay {
    pub fn new(conf: Table, is_client: bool) -> Relay {
        let conf = Rc::new(conf);
        let address = format!("{}:{}", config::get_str(&conf, "local_address"),
                                       config::get_i64(&conf, "local_port"));

        let socket_addr = match str2addr4(&address) {
            Some(addr) => addr,
            None => {
                error!("invalid socket address: {}", address);
                panic!();
            }
        };
        let tcp_listener = match TcpListener::bind(&SocketAddr::V4(socket_addr)) {
            Ok(listener) => {
                if is_client {
                    info!("ssclient listen on {}", address);
                } else {
                    info!("ssserver listen on {}", address);
                }

                listener
            }
            Err(e) => {
                error!("cannot bind address {} because {}", address, e);
                panic!();
            }
        };
        let dns_resolver = Rc::new(RefCell::new(DNSResolver::new(None, None)));

        Relay {
            is_client: is_client,
            conf: conf,
            tcp_listener: tcp_listener,
            dns_resolver: dns_resolver.clone(),
            processors: Holder::new_exclude_from(vec![RELAY_TOKEN, DNS_RESOLVER_TOKEN]),
        }
    }

    pub fn add_processor(&mut self, processor: Rc<RefCell<Processor>>) -> Option<Token> {
        self.processors.add(processor)
    }

    pub fn remove_processor(&mut self, token: Token) -> Option<Rc<RefCell<Processor>>> {
        self.processors.del(token)
    }

    fn add_to_loop(&mut self, token: Token, event_loop: &mut EventLoop<Relay>, events: EventSet) -> bool {
        match event_loop.register(&self.tcp_listener, token, events, PollOpt::edge()) {
            Ok(_) => true,
            _ => false
        }
    }

    pub fn run(&mut self) {
        let mut event_loop = EventLoop::new().unwrap();

        assert!(self.add_to_loop(RELAY_TOKEN, &mut event_loop, get_basic_events()));
        assert!(self.dns_resolver.borrow_mut().add_to_loop(DNS_RESOLVER_TOKEN, &mut event_loop, get_basic_events()));

        event_loop.run(self).unwrap();
    }
}

impl Handler for Relay {
    type Timeout = i32;
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        let result = match token {
            RELAY_TOKEN => {
                self.process(event_loop, token, events)
            }
            DNS_RESOLVER_TOKEN => {
                self.dns_resolver.borrow_mut().process(event_loop, token, events)
            }
            token @ Token(_) => {
                match self.processors.get(token) {
                    Some(processor) => processor.borrow_mut().process(event_loop, token, events),
                    _ => {
                        info!("got events {:?} after token {:?} destroyed", events, token);
                        return;
                    }
                }
            }
        };

        match result {
            ProcessResult::Success => { }
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
    fn process(&mut self, event_loop: &mut EventLoop<Relay>, _token: Token, events: EventSet) -> ProcessResult<Vec<Token>> {
        if events.is_error() {
            error!("events error happened on Relay");
            return ProcessResult::Success;
        }

        match self.tcp_listener.accept() {
            Ok(Some((conn, _addr))) => {
                debug!("create processor for {}", _addr);
                let tcp_processor = Rc::new(RefCell::new(TCPProcessor::new(self.conf.clone(),
                                                                           conn,
                                                                           self.dns_resolver.clone(),
                                                                           self.is_client)));
                let mut tokens = vec![];

                let local_token = self.add_processor(tcp_processor.clone());
                if local_token.is_some() {
                    let token = local_token.unwrap();
                    tokens.push(token);

                    if !tcp_processor.borrow_mut().add_to_loop(token,
                                                               event_loop,
                                                               get_basic_events() | EventSet::hup(),
                                                               true) {
                       return ProcessResult::Failed(tokens);
                    }
                }

                let remote_token = self.add_processor(tcp_processor.clone());
                if remote_token.is_some() {
                    let token = remote_token.unwrap();
                    tokens.push(token);

                    tcp_processor.borrow_mut().set_remote_token(token);
                    self.dns_resolver.borrow_mut().add_caller(token, tcp_processor);
                }

                if tokens.len() != 2 {
                    error!("cannot generate token for TCP processor");
                    return ProcessResult::Failed(tokens);
                }
            }
            Ok(None) => { }
            Err(e) => info!("accept TCP connection failed: {}", e),
        }

        ProcessResult::Success
    }

    fn destroy(&mut self, _event_loop: &mut EventLoop<Relay>) {
        unreachable!();
    }

    fn is_destroyed(&self) -> bool {
        false
    }
}
