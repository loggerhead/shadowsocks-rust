extern crate mio;
extern crate env_logger;
extern crate shadowsocks;

use std::rc::Rc;
use std::cell::RefCell;

use shadowsocks::shell;
use shadowsocks::relay::Relay;

fn main() {
    env_logger::init().unwrap();
    let config = shell::get_config().expect("Invalid configuration");

    Relay::new().run();
}
