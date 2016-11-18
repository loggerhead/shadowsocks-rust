#[macro_use(o, slog_log, slog_debug, slog_info, slog_warn, slog_error, slog_trace)]
extern crate slog;
#[macro_use(debug, info, warn, error, trace)]
extern crate slog_scope;
extern crate shadowsocks;

use std::thread::spawn;
use std::process::exit;

use shadowsocks::config;
use shadowsocks::relay::{TcpRelay, UdpRelay};

fn main() {
    let conf = config::gen_config().unwrap_or_else(|e| {
        println!("{:?}", e);
        exit(1);
    });

    let childs = vec![
        {
            let conf = conf.clone();
            spawn(move || {
                TcpRelay::new(&conf).and_then(|r| r.run())
                    .unwrap_or_else(|e| error!("{:?}", e))
            })
        },
        {
            spawn(move || {
                UdpRelay::new(&conf).and_then(|r| r.run())
                    .unwrap_or_else(|e| error!("{:?}", e))
            })
        },
    ];

    for child in childs {
        let _ = child.join();
    }
}
