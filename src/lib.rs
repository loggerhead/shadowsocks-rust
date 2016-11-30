#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", allow(collapsible_if,
                                    needless_return,
                                    needless_range_loop,
                                    or_fun_call))]

#[macro_use]
#[cfg(target_family = "unix")]
extern crate sig;
#[macro_use]
extern crate try_opt;
#[macro_use]
extern crate lazy_static;
#[macro_use(o, slog_log, slog_debug, slog_info, slog_warn, slog_error, slog_trace)]
extern crate slog;
#[macro_use(debug, info, warn, error, trace)]
extern crate slog_scope;
extern crate slog_term;
extern crate slog_stream;
extern crate mio;
extern crate rand;
extern crate toml;
extern crate clap;
extern crate regex;
extern crate chrono;
extern crate byteorder;
extern crate lru_cache;
extern crate rustc_serialize;
extern crate crypto as crypto_crate;
#[cfg(feature = "openssl")]
extern crate openssl as openssl_crate;

#[macro_use]
pub mod util;
#[macro_use]
pub mod network;
pub mod mode;
pub mod relay;
pub mod config;
pub mod crypto;
pub mod protocol;
pub mod my_logger;
pub mod my_daemonize;
