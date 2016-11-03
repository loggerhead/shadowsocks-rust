use std::io;
use std::io::Result;
use std::str::FromStr;
use std::time::SystemTime;
use std::cmp::{Ord, Ordering};
use std::collections::VecDeque;

use mio::Token;
use rand::{thread_rng, ThreadRng, Rng};

use collections::Dict;
use config::Config;

macro_rules! err {
    (InvalidMode, $m:expr) => ( io_err!("invalid mode {}", $m) );
    (InvalidPort, $m:expr) => ( io_err!("invalid port {}", $m) );
}

type AddrPortPair = (String, u16);

#[derive(PartialEq)]
enum Mode {
    Fast,
    Balance,
    None,
}

pub struct ServerChooser {
    rng: ThreadRng,
    mode: Mode,
    servers: Dict<AddrPortPair, RttRecord>,
    records: Dict<Token, VecDeque<(AddrPortPair, SystemTime)>>,
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
            records: Dict::default(),
        })
    }

    pub fn choose(&mut self, token: Token) -> Option<(String, u16)> {
        match self.mode {
            Mode::Fast => {
                let addr_port = try_opt!(self.choose_by_weight());
                self.record(token, addr_port.clone());
                // TODO: change info to debug
                info!("choose ssserver {}:{}", addr_port.0, addr_port.1);
                Some(addr_port)
            }
            Mode::Balance => self.random_choose(),
            _ => unreachable!(),
        }
    }

    fn random_choose(&mut self) -> Option<(String, u16)> {
        let addr_port_pairs: Vec<&(String, u16)> = self.servers.keys().collect();
        let &&(ref addr, port) = try_opt!(self.rng.choose(&addr_port_pairs));
        Some((addr.clone(), port))
    }

    // the compute need O(n) time. But for normal user,
    // the servers number is small, so the compute time is acceptable
    fn choose_by_weight(&mut self) -> Option<(String, u16)> {
        let mut server = None;
        let mut rtt = None;

        for (s, r) in self.servers.iter() {
            if rtt.is_none() {
                server = Some(s);
                rtt = Some(r);
            } else if rtt > Some(r) {
                server = Some(s);
                rtt = Some(r);
            }
        }

        server.map(|&(ref addr, port)| (addr.clone(), port))
    }

    fn record(&mut self, token: Token, addr_port: AddrPortPair) {
        let times = self.records.entry(token).or_insert(VecDeque::new());
        times.push_back((addr_port, SystemTime::now()));
    }

    pub fn update(&mut self, token: Token) {
        if self.mode == Mode::Fast {
            // because this method call only after `record` is called,
            // so this `unwrap` should NOT failed
            let times = self.records.get_mut(&token).unwrap();
            if let Some((addr_port, time)) = times.pop_front() {
                let r = self.servers.get_mut(&addr_port).unwrap();
                r.update(time);
            }
        }
    }
}

#[derive(Eq, Debug)]
struct RttRecord {
    // lower is prefer
    weight: u32,
    estimated: u32,
    dev: u32,
}

impl RttRecord {
    fn new() -> RttRecord {
        RttRecord {
            weight: 0,
            estimated: 0,
            dev: 0,
        }
    }

    fn update(&mut self, last_activity: SystemTime) {
        let dt = last_activity.elapsed()
            .map(|d| d.as_secs() as u32 * 1000 + d.subsec_nanos() / 1000000);
        if let Ok(elapsed_ms) = dt {
            let mut estimated = self.estimated as f32;
            let mut dev = self.dev as f32;

            estimated = 0.875 * estimated + 0.125 * elapsed_ms as f32;
            dev = 0.75 * dev + 0.25 * (elapsed_ms as f32 - estimated).abs();

            self.estimated = estimated as u32;
            self.dev = dev as u32;
            self.weight = self.estimated + 4 * self.dev;
        }
    }
}

impl Ord for RttRecord {
    fn cmp(&self, other: &RttRecord) -> Ordering {
        self.weight.cmp(&other.weight)
    }
}

impl PartialOrd for RttRecord {
    fn partial_cmp(&self, other: &RttRecord) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RttRecord {
    fn eq(&self, other: &RttRecord) -> bool {
        self.weight == other.weight
    }
}
