use std::rc::{Rc, Weak};
use std::cell::RefCell;

use mio::{Token, Handler, EventSet, EventLoop};
use mio::util::Slab;

use asyncdns::DNSResolver;
use tcprelay::TcpRelay;


pub struct Dispatcher {
    handlers: Slab<Processor>,
    event_loop: Rc<RefCell<EventLoop<Dispatcher>>>,
}

impl Dispatcher {
    pub fn new() -> Dispatcher {
        Dispatcher {
            handlers: Slab::new_starting_at(Token(0), 8192),
            event_loop: Rc::new(RefCell::new(EventLoop::new().unwrap())),
        }
    }

    pub fn add_handler(&mut self, handler: Processor) -> Option<Token> {
        self.handlers.insert_with(move |_token| handler)
    }

    pub fn get_handler(&mut self, token: Token) -> &mut Processor {
        self.handlers.get_mut(token).unwrap()
    }

    pub fn get_event_loop(&self) -> Rc<RefCell<EventLoop<Dispatcher>>> {
        self.event_loop.clone()
    }

    pub fn run(&mut self) {
        let mut event_loop = self.get_event_loop();
        event_loop.borrow_mut().run(self).expect("Error when start event loop");
    }
}

impl Handler for Dispatcher {
    type Timeout = i32;
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Dispatcher>, token: Token, events: EventSet) {
        self.handlers[token].handle_event(event_loop, events);
    }
}

macro_rules! register_handler {
    ($me:ident, $holder:ident, $processor_type:path, $events:expr) => (
        {
            let token = $holder.add_handler($processor_type($me)).unwrap();
            let event_loop = $holder.get_event_loop();

            match $holder.get_handler(token) {
                &mut $processor_type(ref this) => {
                    if let Some(ref sock) = this.sock {
                        event_loop.borrow_mut().register(
                            sock,
                            token,
                            $events,
                            PollOpt::level()
                        ).unwrap();
                    }
                }
                _ => {
                    panic!("Register a error type of handler");
                }
            }

            token
        }
    )
}


pub enum Processor {
    DNS(DNSResolver),
    TCP(TcpRelay),
}

impl Processor {
    fn handle_event(&mut self, event_loop: &mut EventLoop<Dispatcher>, events: EventSet) {
        match self {
            // &mut Processor::DNS(ref mut this) => this.handle_event(event_loop, events),
            // &mut Processor::TCP(ref mut this) => this.handle_event(event_loop, events),
            _ => unreachable!(),
        }
    }
}