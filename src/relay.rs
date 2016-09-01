use std::rc::Rc;
use std::cell::RefCell;
use std::net::{SocketAddr};
use std::sync::mpsc::{channel, Sender, Receiver};

use mio::util::Slab;
use mio::{Token, Handler, EventSet, EventLoop, PollOpt};
use mio::tcp::{TcpListener};
use toml::Table;

use config;
use network::str2addr4;
use asyncdns::DNSResolver;
use util::get_basic_events;
use tcp_processor::TCPProcessor;


const RELAY_TOKEN: Token = Token(0);


pub trait Processor {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet);
    fn destroy(&mut self, event_loop: &mut EventLoop<Relay>);
    fn is_destroyed(&self) -> bool;
}


pub struct Relay {
    is_local: bool,
    conf: Rc<Table>,
    notifier: Rc<Sender<Token>>,
    waiter: Receiver<Token>,
    tcp_listener: TcpListener,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    processors: Slab<Rc<RefCell<Processor>>>,
}


impl Relay {
    pub fn new(conf: Table, is_local: bool) -> Relay {
        let conf = Rc::new(conf);
        let address = format!("{}:{}", config::get_str(&conf, "local_address"),
                                       config::get_i64(&conf, "local_port"));

        let (notifier, waiter) = channel();
        let notifier = Rc::new(notifier);
        let socket_addr = match str2addr4(&address) {
            Some(addr) => addr,
            None => {
                error!("invalid socket address: {}", address);
                panic!();
            }
        };
        let tcp_listener = match TcpListener::bind(&SocketAddr::V4(socket_addr)) {
            Ok(listener) => {
                if is_local {
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
        let dns_resolver = Rc::new(RefCell::new(DNSResolver::new(notifier.clone(), None, None)));
        let beginning_token = Token(RELAY_TOKEN.as_usize() + 1);

        Relay {
            is_local: is_local,
            conf: conf,
            notifier: notifier,
            waiter: waiter,
            tcp_listener: tcp_listener,
            dns_resolver: dns_resolver.clone(),
            processors: Slab::new_starting_at(beginning_token, 8192),
        }
    }

    pub fn add_processor(&mut self, processor: Rc<RefCell<Processor>>) -> Option<Token> {
        self.processors.insert(processor).ok()
    }

    pub fn get_dns_resolver(&self) -> Rc<RefCell<DNSResolver>> {
        self.dns_resolver.clone()
    }

    fn add_to_loop(&mut self, token: Token, event_loop: &mut EventLoop<Relay>, events: EventSet) -> Option<()> {
        event_loop.register(&self.tcp_listener, token, events, PollOpt::level()).ok()
    }


    pub fn run(&mut self) {
        let mut event_loop = EventLoop::new().unwrap();

        let dns_resolver = self.get_dns_resolver();
        let token = self.add_processor(dns_resolver).unwrap();

        self.dns_resolver.borrow_mut().add_to_loop(token, &mut event_loop, get_basic_events());
        self.add_to_loop(RELAY_TOKEN, &mut event_loop, get_basic_events());

        debug!("start event loop");
        event_loop.run(self).unwrap();
    }
}

impl Handler for Relay {
    type Timeout = i32;
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        while let Ok(t) = self.waiter.try_recv() {
            self.processors.remove(t);
            self.dns_resolver.borrow_mut().remove_caller(t);
        }

        match token {
            RELAY_TOKEN => {
                self.process(event_loop, token, events);
            }
            token @ Token(_) => {
                if self.processors[token].borrow_mut().is_destroyed() {
                    return;
                }

                self.processors[token].borrow_mut().process(event_loop, token, events);
            }
        }
    }
}


impl Processor for Relay {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>, _token: Token, events: EventSet) {
        if events.is_error() {
            error!("events error happened on Relay");
            return;
        }

        match self.tcp_listener.accept() {
            Ok(Some((conn, _addr))) => {
                debug!("create processor for {}", _addr);
                let tcp_processor = Rc::new(RefCell::new(TCPProcessor::new(self.conf.clone(),
                                                                           self.notifier.clone(),
                                                                           conn,
                                                                           self.get_dns_resolver(),
                                                                           self.is_local)));
                // register local socket of tcp_processor
                let add_result = match self.add_processor(tcp_processor.clone()) {
                    Some(token) => {
                        tcp_processor.borrow_mut().add_to_loop(token,
                                                               event_loop,
                                                               get_basic_events() | EventSet::hup(),
                                                               true)
                    }
                    None => None,
                };
                if add_result.is_none() {
                    error!("register TCP processor to eventloop failed");
                    return;
                }

                // get remote token of tcp_processor
                if let Some(token) = self.add_processor(tcp_processor.clone()) {
                    tcp_processor.borrow_mut().set_remote_token(token);
                    let dns_resolver = self.get_dns_resolver();
                    dns_resolver.borrow_mut().add_caller(token, tcp_processor);
                } else {
                    error!("cannot generate remote token for TCP processor");
                    tcp_processor.borrow_mut().destroy(event_loop);
                }
            }
            Ok(None) => {
                debug!("Accept nothing...");
            }
            Err(e) => {
                error!("Error when accept TCP connection: {}", e);
            }
        }
    }

    fn destroy(&mut self, event_loop: &mut EventLoop<Relay>) {
        unimplemented!();
    }

    fn is_destroyed(&self) -> bool {
        unimplemented!();
    }
}
