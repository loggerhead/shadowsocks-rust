#[macro_use(o, slog_log, slog_debug, slog_info, slog_warn, slog_error, slog_trace)]
extern crate slog;
#[macro_use(debug, info, warn, error, trace)]
extern crate slog_scope;
extern crate shadowsocks;

use std::thread::spawn;

use shadowsocks::relay::{TcpRelay, UdpRelay};

fn main() {
    let childs = vec![
        {
            spawn(move || {
                TcpRelay::new().and_then(|r| r.run())
                    .unwrap_or_else(|e| error!("{:?}", e))
            })
        },
        {
            spawn(move || {
                UdpRelay::new().and_then(|r| r.run())
                    .unwrap_or_else(|e| error!("{:?}", e))
            })
        },
    ];

    for child in childs {
        let _ = child.join();
    }
}
