use std::rc::Rc;
use std::cell::RefCell;
use std::io::Result;

use mio::{Token, Handler, EventSet, EventLoop, PollOpt, Evented};
use mio::util::Slab;


pub trait Processor {
    fn handle_event(&mut self, events: EventSet);
}


pub struct Dispatcher {
    handlers: Slab<Rc<RefCell<Processor>>>,
    event_loop: Rc<RefCell<EventLoop<Dispatcher>>>,
}


impl Dispatcher {
    pub fn new() -> Dispatcher {
        Dispatcher {
            handlers: Slab::new_starting_at(Token(0), 8192),
            event_loop: Rc::new(RefCell::new(EventLoop::new().unwrap())),
        }
    }

    pub fn add_handler(&mut self, handler: Rc<RefCell<Processor>>) -> Option<Token> {
        self.handlers.insert_with(move |_token| handler)
    }

    pub fn get_event_loop(&self) -> Rc<RefCell<EventLoop<Dispatcher>>> {
        self.event_loop.clone()
    }

    pub fn register<E: ?Sized + Evented>(&self, io: &E, token: Token, interest: EventSet) -> Result<()> {
        self.event_loop.borrow_mut().register(
            io,
            token,
            interest,
            PollOpt::level()
        )
    }

    pub fn run(&mut self) {
        let event_loop = self.get_event_loop();
        event_loop.borrow_mut().run(self).expect("Error when start event loop");
    }
}

impl Handler for Dispatcher {
    type Timeout = i32;
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<Dispatcher>, token: Token, events: EventSet) {
        let mut handler = self.handlers[token].borrow_mut();
        handler.handle_event(events);
    }
}
