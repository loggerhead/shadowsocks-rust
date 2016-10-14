#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", allow(collapsible_if, needless_return, needless_range_loop))]

#[macro_use]
extern crate try_opt;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

extern crate mio;
extern crate fnv;
extern crate rand;
extern crate toml;
extern crate clap;
extern crate regex;
extern crate crypto;
extern crate chrono;
extern crate ansi_term;
extern crate byteorder;
extern crate lru_time_cache;

#[macro_use]
pub mod util;
#[macro_use]
pub mod relay;
pub mod config;
pub mod socks5;
pub mod network;
pub mod encrypt;
pub mod asyncdns;
pub mod my_logger;
pub mod collections;
pub mod tcp_processor;
