use std::sync::Arc;
use std::time::SystemTime;
use std::collections::{VecDeque, HashMap};

use mio::Token;
use lru_cache::LruCache;
use rand::{thread_rng, ThreadRng, Rng};

use config::{CONFIG, ProxyConfig};
use super::{Mode, RttRecord};

const CACHE_SIZE: usize = 1024;

pub struct ServerChooser {
    rng: ThreadRng,
    rtts: HashMap<Arc<ProxyConfig>, RttRecord>,
    activities: LruCache<Token, VecDeque<SystemTime>>,
}

impl ServerChooser {
    pub fn new() -> ServerChooser {
        let mut rtts = HashMap::new();

        // reduce some compute...
        if cfg!(feature = "sslocal") {
            for server_conf in CONFIG.server_confs.as_ref().unwrap() {
                rtts.insert(server_conf.clone(), RttRecord::new());
            }
        }

        ServerChooser {
            rng: thread_rng(),
            rtts: rtts,
            activities: LruCache::new(CACHE_SIZE),
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
            if !self.activities.contains_key(&token) {
                self.activities.insert(token, VecDeque::new());
            }

            if let Some(times) = self.activities.get_mut(&token) {
                times.push_back(SystemTime::now());
            }
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
