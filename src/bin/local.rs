extern crate mio;
extern crate env_logger;

extern crate shadowsocks;

use mio::EventLoop;

use shadowsocks::shell;
use shadowsocks::eventloop;
use shadowsocks::eventloop::Dispatcher;
use shadowsocks::asyncdns::DNSResolver;

fn main() {
    env_logger::init().unwrap();
    let config = shell::get_config().expect("Invalid configuration");

    let dns_resolver = DNSResolver::new(None, None);

    let mut dispatcher = Dispatcher::new();
    dns_resolver.add_to_loop(&mut dispatcher);

    dispatcher.run();
}