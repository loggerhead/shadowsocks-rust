#[macro_use]
extern crate log;
extern crate clap;
extern crate shadowsocks;

use std::process::exit;

use shadowsocks::config;
use shadowsocks::relay::Relay;
use shadowsocks::my_logger;

fn main() {
    let conf = config::gen_config().unwrap_or_else(|e| {
        println!("config error: {}", e);
        exit(1);
    });
    my_logger::init(&conf).unwrap_or_else(|e| {
        println!("init logger failed: {}", e);
        exit(1);
    });

    Relay::new(conf).run();
}