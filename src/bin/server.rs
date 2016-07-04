extern crate mio;
extern crate env_logger;

extern crate shadowsocks;

use mio::EventLoop;

use shadowsocks::eventloop;
use shadowsocks::eventloop::Dispatcher;
use shadowsocks::asyncdns::DNSResolver;

fn main() {
    env_logger::init().unwrap();

    let dns_resolver = DNSResolver::new(None, None);

    run_server(dns_resolver);
}

fn run_server(dns_resolver: DNSResolver) {
    let mut event_loop = EventLoop::new().unwrap();
    let mut dispatcher = Dispatcher::new();

    dns_resolver.add_to_loop(&mut event_loop, &mut dispatcher);

    eventloop::run(&mut event_loop, &mut dispatcher);
}