extern crate mio;
extern crate env_logger;
extern crate shadowsocks;

use std::rc::Rc;
use std::cell::RefCell;

use shadowsocks::shell;
use shadowsocks::eventloop::Dispatcher;
use shadowsocks::asyncdns::DNSResolver;
use shadowsocks::tcprelay::TCPRelay;

fn main() {
    env_logger::init().unwrap();
    let config = shell::get_config().expect("Invalid configuration");

    let dispatcher = Rc::new(RefCell::new(Dispatcher::new()));
    let dns_resolver = DNSResolver::new(None, None)
                            .add_to_loop(dispatcher.clone())
                            .unwrap();

    let tcp_server = TCPRelay::new(dns_resolver.clone(), true);
    tcp_server.add_to_loop(dispatcher.clone()).unwrap();

    dispatcher.borrow_mut().run();
}
