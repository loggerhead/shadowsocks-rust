#[macro_use]
extern crate log;
extern crate clap;
extern crate shadowsocks;

use std::process::exit;

use shadowsocks::config;
use shadowsocks::relay::Relay;
use shadowsocks::util::init_env_logger;

fn main() {
    init_env_logger();
    // TODO: parse config from command line
    // https://crates.io/crates/clap
    let conf = config::get_config("tests/config/server_conf.toml").unwrap_or_else(|e| {
        error!("config error: {}", e);
        exit(1);
    });

    Relay::new(conf, false).run();
}
