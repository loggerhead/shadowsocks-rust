use std::io;
use std::io::Result;
use std::str::FromStr;
use std::time::SystemTime;

use rand::{thread_rng, ThreadRng, Rng};

use collections::Dict;
use config::Config;

macro_rules! err {
    (InvalidMode, $m:expr) => ( io_err!("invalid mode {}", $m) );
    (InvalidPort, $m:expr) => ( io_err!("invalid port {}", $m) );
}

pub enum Mode {
    Fast,
    Balance,
    None,
}

pub struct ServerChooser {
    rng: ThreadRng,
    mode: Mode,
    servers: Dict<(String, u16), RttRecord>,
}

impl ServerChooser {
    pub fn new(conf: &Config) -> Result<ServerChooser> {
        let mut mode = Mode::None;
        let mut servers = Dict::default();

        if cfg!(feature = "sslocal") {
            let conf_mode = conf["mode"].as_str().unwrap();
            mode = if conf_mode == "fast" {
                Mode::Fast
            } else if conf_mode == "balance" {
                Mode::Balance
            } else {
                return Err(err!(InvalidMode, conf_mode));
            };

            let conf_servers = conf["servers"].as_slice().unwrap();
            for server in conf_servers {
                let parts: Vec<&str> = server.as_str().unwrap().splitn(2, ':').collect();
                let addr = parts[0].to_string();
                let port = try!(u16::from_str(parts[1]).map_err(|_| err!(InvalidPort, server)));
                servers.insert((addr, port), RttRecord::new());
            }
        }

        Ok(ServerChooser {
            rng: thread_rng(),
            mode: mode,
            servers: servers,
        })
    }

    pub fn choose(&mut self) -> Option<(String, u16)> {
        match self.mode {
            Mode::Fast => self.choose_by_weight(),
            Mode::Balance => self.random_choose(),
            _ => unreachable!(),
        }
    }

    fn random_choose(&mut self) -> Option<(String, u16)> {
        let addr_port_pairs: Vec<&(String, u16)> = self.servers.keys().collect();
        let &&(ref addr, port) = try_opt!(self.rng.choose(&addr_port_pairs));
        Some((addr.clone(), port))
    }

    // TODO: finish this
    fn choose_by_weight(&mut self) -> Option<(String, u16)> {
        None
    }
}

struct RttRecord {
    // lower is prefer
    weight: i32,
    last_activity: SystemTime,
    estimated: i32,
    dev: i32,
}

impl RttRecord {
    fn new() -> RttRecord {
        RttRecord {
            weight: 0,
            last_activity: SystemTime::now(),
            estimated: 0,
            dev: 0,
        }
    }

    fn update(&mut self) {
    }
}
