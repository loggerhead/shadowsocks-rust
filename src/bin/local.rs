#[macro_use] extern crate log;
extern crate mio;
extern crate env_logger;
extern crate shadowsocks;

use shadowsocks::shell;
use shadowsocks::relay::Relay;

fn main() {
    env_logger::init().unwrap();
    let _config = shell::get_config().expect("Invalid configuration");

    Relay::new().run();
}
