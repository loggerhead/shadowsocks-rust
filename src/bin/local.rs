extern crate clap;
extern crate env_logger;
extern crate shadowsocks;

use shadowsocks::config;
use shadowsocks::relay::Relay;

fn main() {
    env_logger::init().unwrap();
    // TODO: parse config from command line
    // https://crates.io/crates/clap
    let conf = config::get_config("tests/config/local_conf.toml").unwrap_or_else(|e| {
        println!("{}", e);
        panic!();
    });

    Relay::new(conf, true).run();
}
