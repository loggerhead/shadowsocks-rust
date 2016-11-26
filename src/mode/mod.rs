use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;
use std::cmp::{Ord, Ordering};
use std::collections::VecDeque;

use mio::Token;
use rand::{thread_rng, ThreadRng, Rng};

use config::{CONFIG, ProxyConfig};
use collections::Dict;

#[derive(PartialEq, Clone, Copy)]
pub enum Mode {
    Fast,
    Balance,
    None,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Mode::Fast => write!(f, "fast"),
            Mode::Balance => write!(f, "balance"),
            Mode::None => write!(f, "none"),
        }
    }
}

impl fmt::Debug for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct ServerChooser {
    rng: ThreadRng,
    rtts: Dict<Arc<ProxyConfig>, RttRecord>,
    activities: Dict<Token, VecDeque<SystemTime>>,
}

impl ServerChooser {
    pub fn new() -> ServerChooser {
        let mut rtts = Dict::default();

        // reduce some compute...
        if cfg!(feature = "sslocal") {
            for server_conf in CONFIG.server_confs.as_ref().unwrap() {
                rtts.insert(server_conf.clone(), RttRecord::new());
            }
        }

        ServerChooser {
            rng: thread_rng(),
            rtts: rtts,
            activities: Dict::default(),
        }
    }

    pub fn choose(&mut self) -> Option<Arc<ProxyConfig>> {
        match CONFIG.mode {
            Mode::Fast => self.choose_by_weight(),
            Mode::Balance => self.random_choose(),
            _ => unreachable!(),
        }
    }

    fn random_choose(&mut self) -> Option<Arc<ProxyConfig>> {
        let server_confs: Vec<&Arc<ProxyConfig>> = self.rtts.keys().collect();
        let &server_conf = try_opt!(self.rng.choose(&server_confs));
        Some(server_conf.clone())
    }

    // This method will choose the last latency server with 80% probability,
    // and choose other servers with 20% probability.
    fn choose_by_weight(&mut self) -> Option<Arc<ProxyConfig>> {
        let is_choose_min = self.rng.gen::<u8>() < (0.8 * u8::max_value() as f32) as u8;
        if is_choose_min {
            let mut min_conf = None;
            let mut min_rtt = None;

            for (conf, rtt) in &self.rtts {
                if min_rtt.is_none() || min_rtt > Some(rtt) {
                    min_rtt = Some(rtt);
                    min_conf = Some(conf);
                }
            }

            min_conf.cloned()
        } else {
            self.random_choose()
        }
    }

    pub fn record(&mut self, token: Token) {
        if Mode::Fast == CONFIG.mode {
            let times = self.activities.entry(token).or_insert_with(VecDeque::new);
            times.push_back(SystemTime::now());
        }
    }

    pub fn update(&mut self, token: Token, server_conf: &Arc<ProxyConfig>) {
        if Mode::Fast == CONFIG.mode {
            let time = self.activities.get_mut(&token).and_then(|times| times.pop_front());
            match time {
                Some(time) => {
                    self.rtts.get_mut(server_conf).map(|rtt| rtt.update(&time));
                }
                None => {
                    self.activities.remove(&token);
                }
            }
        }
    }

    pub fn punish(&mut self, token: Token, server_conf: &Arc<ProxyConfig>) {
        if Mode::Fast == CONFIG.mode {
            self.activities.remove(&token);
            self.rtts.get_mut(server_conf).map(|rtt| rtt.punish());
        }
    }
}

#[derive(Eq, Debug, Copy, Clone)]
struct RttRecord {
    rto: u64,
    rtt: u32,
    dev: u32,
    last_activity: SystemTime,
}

impl RttRecord {
    fn new() -> RttRecord {
        RttRecord {
            rto: 0,
            rtt: 0,
            dev: 0,
            last_activity: SystemTime::now(),
        }
    }

    fn update_rto(&mut self) {
        self.rto = self.rtt as u64 + 4 * self.dev as u64;
    }

    fn update(&mut self, last_activity: &SystemTime) {
        self.last_activity = last_activity.clone();
        let dt = last_activity.elapsed()
            .map(|d| d.as_secs() as u32 * 1000 + d.subsec_nanos() / 1000000);

        if let Ok(elapsed_ms) = dt {
            let mut rtt = self.rtt as f32;
            let mut dev = self.dev as f32;

            rtt = 0.875 * rtt + 0.125 * elapsed_ms as f32;
            dev = 0.75 * dev + 0.25 * (elapsed_ms as f32 - rtt).abs();

            self.rtt = rtt as u32;
            self.dev = dev as u32;
            self.update_rto();
        }
    }

    fn punish(&mut self) {
        let dt = self.last_activity
            .elapsed()
            .map(|d| d.as_secs() as u32 * 1000 + d.subsec_nanos() / 1000000);

        if let Ok(elapsed_ms) = dt {
            // self.dev = 2 * self.dev + elapsed_ms
            let dev = self.dev
                .checked_mul(2)
                .and_then(|d| d.checked_add(elapsed_ms));

            match dev {
                Some(dev) => self.dev = dev,
                None => self.dev = u32::max_value(),
            }
            self.update_rto();
        }
    }
}

impl Ord for RttRecord {
    fn cmp(&self, other: &RttRecord) -> Ordering {
        self.rto.cmp(&other.rto)
    }
}

impl PartialOrd for RttRecord {
    fn partial_cmp(&self, other: &RttRecord) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RttRecord {
    fn eq(&self, other: &RttRecord) -> bool {
        self.rto == other.rto
    }
}
