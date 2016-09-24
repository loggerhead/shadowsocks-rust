#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", allow(collapsible_if, needless_range_loop))]

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
extern crate lru_time_cache;
extern crate byteorder;

#[macro_use]
pub mod util;
pub mod relay;
pub mod config;
pub mod common;
pub mod network;
pub mod encrypt;
pub mod asyncdns;
pub mod my_logger;
pub mod tcp_processor;
