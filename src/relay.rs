use std::str::FromStr;
use std::rc::Rc;
use std::cell::RefCell;
use std::net::{SocketAddr, SocketAddrV4};

use mio::util::Slab;
use mio::{Token, Handler, EventSet, EventLoop, PollOpt, Evented};
use mio::tcp::{TcpListener};

use asyncdns::DNSResolver;
use tcp_processor::TCPProcessor;


const RELAY_TOKEN: Token = Token(0);
const DNS_RESOLVER_TOKEN: Token = Token(1);
const BEGINNING_TOKEN: Token = Token(2);

pub trait Processor {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet);
}


pub struct Relay {
    listener: TcpListener,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    processors: Slab<Rc<RefCell<Processor>>>,
}


impl Relay {
    pub fn new() -> Relay {
        let socket_addr = SocketAddrV4::from_str("127.0.0.1:8488").unwrap();
        let tcp_listener = TcpListener::bind(&SocketAddr::V4(socket_addr)).unwrap();
        let dns_resolver = Rc::new(RefCell::new(DNSResolver::new(None, None)));

        Relay {
            listener: tcp_listener,
            dns_resolver: dns_resolver.clone(),
            processors: Slab::new_starting_at(BEGINNING_TOKEN, 8192),
        }
    }

    pub fn add_processor(&mut self, processor: Rc<RefCell<Processor>>) -> Option<Token> {
        self.processors.insert_with(move |_token| processor)
    }

    pub fn remove_processor(&mut self, token: Token) {
        self.processors.remove(token);
    }

    pub fn run(&mut self) {
        let mut event_loop = EventLoop::new().unwrap();
        self.dns_resolver.borrow_mut().add_to_loop(DNS_RESOLVER_TOKEN, &mut event_loop);
        event_loop.run(self).unwrap();
    }
}

impl Handler for Relay {
    type Timeout = i32;
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        match token {
            RELAY_TOKEN => {
                self.process(event_loop, token, events);
            }
            DNS_RESOLVER_TOKEN => {
                self.dns_resolver.borrow_mut().process(event_loop, token, events);
            }
            token @ Token(_) => {
                self.processors[token].borrow_mut().process(event_loop, token, events);
            }
        }
    }
}


impl Processor for Relay {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet) {
        if events.is_error() {
            error!("events error happened on Relay");
        } else {
            match self.listener.accept() {
                Ok(Some((conn, _addr))) => {
                    let tcp_processor = TCPProcessor::new(conn, self.dns_resolver.clone(), true);
                    let tcp_processor = Rc::new(RefCell::new(tcp_processor));

                    let res = match self.add_processor(tcp_processor.clone()) {
                        Some(token) => {
                            tcp_processor.borrow_mut().add_to_loop(token, event_loop, true)
                        }
                        None => None,
                    };
                    if res.is_none() {
                        error!("Cannot add TCP processor to eventloop");
                        return;
                    }

                    if let Some(token) = self.add_processor(tcp_processor.clone()) {
                        tcp_processor.borrow_mut().set_remote_token(token);
                    } else {
                        tcp_processor.borrow_mut().destroy();
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
    }
}
