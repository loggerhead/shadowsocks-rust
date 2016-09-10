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
    let default_config_path = if cfg!(feature = "is_client") {
        "tests/config/client_conf.toml"
    } else {
        "tests/config/server_conf.toml"
    };

    let conf = config::get_config(default_config_path).unwrap_or_else(|e| {
        error!("config error: {}", e);
        exit(1);
    });

    Relay::new(conf).run();
}