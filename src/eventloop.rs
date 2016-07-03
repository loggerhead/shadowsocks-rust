use mio::{Token, Handler, EventSet, EventLoop};
use mio::util::Slab;

use asyncdns::{DNSResolver};


pub trait EventHandler {
    fn handle_event(&mut self, event_loop: &mut EventLoop<Dispatcher>, events: EventSet);
}

pub enum Processor {
    DNS(DNSResolver),
}

impl EventHandler for Processor {
    fn handle_event(&mut self, event_loop: &mut EventLoop<Dispatcher>, events: EventSet) {
        match self {
            &mut Processor::DNS(ref mut this) => this.handle_event(event_loop, events),
        }
    }
}

macro_rules! register_handler {
    ($me:ident, $event_loop:ident, $holder:ident, $processor_type:path, $events:expr) => (
        let token = $holder.add_handler($processor_type($me)).unwrap();

        match $holder.get_handler(token) {
            &mut $processor_type(ref this) => {
                if let Some(ref sock) = this.sock {
                    $event_loop.register(
                        sock,
                        token,
                        $events,
                        PollOpt::level()
                    ).unwrap();
                }
            }
        }
    )
}


pub struct Dispatcher {
    handlers: Slab<Processor>,
}


impl Handler for Dispatcher {
    type Timeout = i32;
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Dispatcher>, token: Token, events: EventSet) {
        self.handlers[token].handle_event(event_loop, events);
    }
}


impl Dispatcher {
    pub fn new() -> Dispatcher {
        Dispatcher {
            handlers: Slab::new_starting_at(Token(0), 8192),
        }
    }

    pub fn add_handler(&mut self, handler: Processor) -> Option<Token> {
        self.handlers.insert_with(move |_token| handler)
    }

    pub fn get_handler(&mut self, token: Token) -> &mut Processor {
        self.handlers.get_mut(token).unwrap()
    }
}


pub fn run(event_loop: &mut EventLoop<Dispatcher>, dispatcher: &mut Dispatcher) {
    event_loop.run(dispatcher).unwrap();
}