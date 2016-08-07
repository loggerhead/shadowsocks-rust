use std::rc::Rc;
use std::cell::RefCell;
use std::net::{SocketAddr, SocketAddrV4};

use mio::util::Slab;
use mio::{Token, Handler, EventSet, EventLoop, PollOpt};
use mio::tcp::{TcpListener};

use network::str2addr4;
use asyncdns::DNSResolver;
use tcp_processor::TCPProcessor;


const RELAY_TOKEN: Token = Token(0);


pub trait Processor {
    fn process(&mut self, event_loop: &mut EventLoop<Relay>, token: Token, events: EventSet);
    fn is_destroyed(&self) -> bool;
}


pub struct Relay {
    tcp_listener: TcpListener,
    dns_resolver: Rc<RefCell<DNSResolver>>,
    processors: Slab<Rc<RefCell<Processor>>>,
}


impl Relay {
    pub fn new() -> Relay {
        let socket_addr = str2addr4("127.0.0.1:8488").unwrap();
        let tcp_listener = TcpListener::bind(&SocketAddr::V4(socket_addr)).unwrap();
        let dns_resolver = Rc::new(RefCell::new(DNSResolver::new(None, None)));
        let beginning_token = Token(RELAY_TOKEN.as_usize() + 1);

        Relay {
            tcp_listener: tcp_listener,
            dns_resolver: dns_resolver.clone(),
            processors: Slab::new_starting_at(beginning_token, 8192),
        }
    }

    pub fn add_processor(&mut self, processor: Rc<RefCell<Processor>>) -> Option<Token> {
        self.processors.insert_with(move |_token| processor)
    }

    pub fn remove_processor(&mut self, token: Token) {
        self.processors.remove(token);
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

        self.dns_resolver.borrow_mut().add_to_loop(token, &mut event_loop, EventSet::readable());
        self.add_to_loop(RELAY_TOKEN, &mut event_loop, EventSet::readable() | EventSet::error());

        debug!("start event loop");
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
            token @ Token(_) => {
                debug!("recevied request of {:?}", token);
                if !self.processors[token].borrow().is_destroyed() {
                    self.processors[token].borrow_mut().process(event_loop, token, events);
                    return;
                }

                self.processors.remove(token);
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
                debug!("new connection from {}", _addr);
                let tcp_processor = TCPProcessor::new(conn, self.get_dns_resolver(), true);
                let tcp_processor = Rc::new(RefCell::new(tcp_processor));

                // register local socket of tcp_processor
                let add_result = match self.add_processor(tcp_processor.clone()) {
                    Some(token) => {
                        tcp_processor.borrow_mut().add_to_loop(token, event_loop, EventSet::readable() | EventSet::hup(), true)
                    }
                    None => None,
                };
                if add_result.is_none() {
                    error!("cannot add TCP processor to eventloop");
                    return;
                }

                // get remote token of tcp_processor
                if let Some(token) = self.add_processor(tcp_processor.clone()) {
                    tcp_processor.borrow_mut().set_remote_token(token);
                } else {
                    error!("cannot add TCP processor to eventloop");
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

    fn is_destroyed(&self) -> bool {
        return false;
    }
}
