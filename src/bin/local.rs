extern crate mio;
extern crate env_logger;
extern crate shadowsocks;

use std::rc::Rc;
use std::cell::RefCell;

use shadowsocks::shell;
use shadowsocks::eventloop::Dispatcher;
use shadowsocks::asyncdns::DNSResolver;

fn main() {
    env_logger::init().unwrap();
    let config = shell::get_config().expect("Invalid configuration");

    let dns_resolver = DNSResolver::new(None, None);

    let dispatcher = Rc::new(RefCell::new(Dispatcher::new()));
    dns_resolver.add_to_loop(dispatcher.clone()).unwrap();

    dispatcher.borrow_mut().run();
}
