#[macro_use] extern crate log;
extern crate mio;
extern crate env_logger;
extern crate shadowsocks;

use shadowsocks::config;
use shadowsocks::relay::Relay;

fn main() {
    env_logger::init().unwrap();
    let conf = config::get_config("server_conf.toml").unwrap_or_else(|e| {
        error!("{}", e);
        panic!();
    });

    Relay::new(conf, false).run();
}
