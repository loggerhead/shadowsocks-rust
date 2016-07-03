extern crate shadowsocks;
extern crate mio;

use mio::EventLoop;

use shadowsocks::asyncdns::{DNSResolver};
use shadowsocks::eventloop;
use shadowsocks::eventloop::{Dispatcher, EventHandler};

fn main() {
    let mut dns_resolver = DNSResolver::new(None, None);

    run_server(dns_resolver);
}

fn run_server(mut dns_resolver: DNSResolver) {
    let mut event_loop = EventLoop::new().unwrap();
    let mut dispatcher = Dispatcher::new();

    dns_resolver.add_to_loop(&mut event_loop, &mut dispatcher);

    eventloop::run(&mut event_loop, &mut dispatcher);
}