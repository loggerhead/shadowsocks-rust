#[macro_use(o, slog_log, slog_debug, slog_info, slog_warn, slog_error, slog_trace)]
extern crate slog;
#[macro_use(debug, info, warn, error, trace)]
extern crate slog_scope;
extern crate shadowsocks;

use std::process::exit;
use std::thread::spawn;

use shadowsocks::my_logger;
use shadowsocks::my_daemonize;
use shadowsocks::config::CONFIG;
use shadowsocks::relay::{TcpRelay, UdpRelay};

fn main() {
    my_daemonize::init(CONFIG.daemon, &CONFIG.pid_file);
    let _ = my_logger::init(CONFIG.log_level, CONFIG.log_file.as_ref()).map_err(|e| {
        println!("init logger failed: {}", e);
        exit(1);
    });

    let childs = vec![
        spawn(|| TcpRelay::new().and_then(|r| r.run())
              .unwrap_or_else(|e| error!("{:?}", e))),
        spawn(|| UdpRelay::new().and_then(|r| r.run())
              .unwrap_or_else(|e| error!("{:?}", e))),
    ];

    for child in childs {
        let _ = child.join();
    }
}
