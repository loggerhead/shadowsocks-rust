use std::io;
use std::io::Result;
use std::str::FromStr;
use std::time::SystemTime;
use std::cmp::{Ord, Ordering};
use std::collections::VecDeque;

use mio::Token;
use regex::Regex;
use lru_time_cache::LruCache;
use rand::{sample, thread_rng, ThreadRng, Rng};

use collections::Dict;
use config::Config;

macro_rules! err {
    (InvalidMode, $m:expr) => ( io_err!("invalid mode {}", $m) );
    (InvalidPort, $m:expr) => ( io_err!("invalid port {}", $m) );
}

type Server = (String, u16);
type Servers = Dict<Server, RttRecord>;
type Activity = (Token, Server, String);
const BUF_SIZE: usize = 1024;

#[derive(PartialEq)]
enum Mode {
    Fast,
    Balance,
    None,
}

pub struct ServerChooser {
    rng: ThreadRng,
    mode: Mode,
    host_to_servers: LruCache<String, Servers>,
    servers: Servers,
    activities: Dict<Activity, VecDeque<SystemTime>>,
}

impl ServerChooser {
    pub fn new(conf: &Config) -> Result<ServerChooser> {
        let mut mode = Mode::None;
        let mut servers = Dict::default();
        let host_to_servers = LruCache::with_capacity(BUF_SIZE);

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
            host_to_servers: host_to_servers,
            servers: servers,
            activities: Dict::default(),
        })
    }

    pub fn choose(&mut self, hostname: &str) -> Option<(String, u16)> {
        match self.mode {
            Mode::Fast => self.choose_by_weight(hostname),
            Mode::Balance => self.random_choose(),
            _ => unreachable!(),
        }
    }

    fn random_choose(&mut self) -> Option<(String, u16)> {
        let addr_port_pairs: Vec<&(String, u16)> = self.servers.keys().collect();
        let &&(ref addr, port) = try_opt!(self.rng.choose(&addr_port_pairs));
        Some((addr.clone(), port))
    }

    fn find_min(servers: &Servers) -> Option<(Server, RttRecord)> {
        let mut rng = thread_rng();
        let (mut server, mut rtt) =
            sample(&mut rng, servers.iter(), 1).pop().map_or((None, None), |(ref s, ref r)| {
                (Some(s.clone()), Some(r.clone()))
            });

        for (s, r1) in servers.iter() {
            match rtt {
                None => {
                    server = Some(s);
                    rtt = Some(r1);
                }
                Some(r2) => {
                    if r1 > r2 {
                        server = Some(s);
                        rtt = Some(r1);
                    }
                }
            }
        }

        server.map(|&(ref addr, port)| ((addr.clone(), port), rtt.unwrap().clone()))
    }

    // the compute need O(n) time. But for normal user,
    // the servers number is small, so the compute time is acceptable
    fn choose_by_weight(&mut self, hostname: &str) -> Option<(String, u16)> {
        let host = self.get_host(hostname);
        let servers = self.default_servers();
        let servers = self.host_to_servers.entry(host.clone()).or_insert(servers);
        Self::find_min(&servers).map(|(server, _)| server)
    }

    fn default_servers(&self) -> Servers {
        let mut servers = Dict::default();
        for (k, _) in &self.servers {
            servers.insert(k.clone(), RttRecord::new());
        }
        servers
    }

    pub fn record(&mut self, token: Token, server: Server, hostname: &str) {
        match self.mode {
            Mode::Fast => {
                let host = self.get_host(hostname);
                let times = self.activities.entry((token, server, host)).or_insert(VecDeque::new());
                times.push_back(SystemTime::now());
            }
            _ => {}
        }
    }

    pub fn update(&mut self, token: Token, server: Server, hostname: &str) {
        match self.mode {
            Mode::Fast => {
                let host = self.get_host(hostname);
                let tsh = (token, server, host);
                let time = self.activities.get_mut(&tsh).and_then(|times| times.pop_front());
                match time {
                    Some(time) => {
                        self.servers.get_mut(&tsh.1).unwrap().update(&time);
                        let servers =
                            self.host_to_servers.entry(tsh.2).or_insert(self.servers.clone());
                        servers.get_mut(&tsh.1).unwrap().update(&time);
                    }
                    None => {
                        self.activities.remove(&tsh);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn punish(&mut self, token: Token, server: Server, hostname: &str) {
        match self.mode {
            Mode::Fast => {
                let host = self.get_host(hostname);
                let tsh = (token, server, host);
                self.activities.remove(&tsh);
                self.host_to_servers.get_mut(&tsh.2).map(|servers| {
                    servers.get_mut(&tsh.1).map(|record| {
                        record.punish();
                    });
                });
            }
            _ => {}
        }
    }

    fn get_host(&self, hostname: &str) -> String {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"[A-Za-z\d-]+(\.ne\.jp|\.net\.ck|\.net\.cm|\.net\.in|\.og\.ao|\.or\.th|\.org\.ck|\.org\.cn|\.org\.ls|\.com\.af|\.com\.ag|\.com\.ai|\.com\.al|\.com\.ar|\.com\.au|\.com\.aw|\.com\.az|\.com\.bb|\.com\.bd|\.com\.bh|\.com\.bi|\.com\.bm|\.com\.bn|\.com\.bo|\.com\.br|\.com\.bs|\.com\.bt|\.com\.by|\.com\.bz|\.com\.cm|\.com\.cn|\.com\.co|\.com\.cu|\.com\.cv|\.com\.cy|\.com\.do|\.com\.dz|\.com\.ec|\.com\.ee|\.com\.eg|\.com\.es|\.com\.et|\.com\.fj|\.com\.ge|\.com\.gh|\.com\.gi|\.com\.gl|\.com\.gn|\.com\.gp|\.com\.gr|\.com\.gt|\.com\.gu|\.com\.hk|\.com\.hn|\.com\.hr|\.com\.ht|\.com\.jm|\.com\.jo|\.com\.kg|\.com\.kh|\.com\.ki|\.com\.kw|\.com\.ky|\.com\.kz|\.com\.lb|\.com\.lc|\.com\.lk|\.com\.lr|\.com\.lv|\.com\.ly|\.com\.mg|\.com\.mk|\.com\.mm|\.com\.mo|\.com\.mt|\.com\.mu|\.com\.mv|\.com\.mw|\.com\.mx|\.com\.my|\.com\.na|\.com\.nf|\.com\.ng|\.com\.ni|\.com\.np|\.com\.nr|\.com\.om|\.com\.pa|\.com\.pe|\.com\.pg|\.com\.ph|\.com\.pk|\.com\.pl|\.com\.pr|\.com\.ps|\.com\.pt|\.com\.py|\.com\.qa|\.com\.ro|\.com\.sa|\.com\.sb|\.com\.sc|\.com\.sg|\.com\.sl|\.com\.sn|\.com\.sv|\.com\.sy|\.com\.tj|\.com\.tn|\.com\.tr|\.com\.tt|\.com\.tw|\.com\.ua|\.com\.uy|\.com\.uz|\.com\.vc|\.com\.ve|\.com\.vi|\.com\.vn|\.com\.ye|\.co\.ao|\.co\.ba|\.co\.bw|\.co\.cc|\.co\.ck|\.co\.cr|\.co\.fk|\.co\.id|\.co\.il|\.co\.im|\.co\.in|\.co\.jp|\.co\.ke|\.co\.kr|\.co\.ls|\.co\.ma|\.co\.mz|\.co\.nl|\.co\.nz|\.co\.th|\.co\.tz|\.co\.ug|\.co\.uk|\.co\.uz|\.co\.ve|\.co\.vi|\.co\.za|\.co\.zm|\.co\.zw|\.ac|\.ad|\.ae|\.af|\.ag|\.ai|\.al|\.am|\.ao|\.aq|\.ar|\.as|\.asia|\.at|\.au|\.aw|\.ax|\.az|\.ba|\.bb|\.bd|\.be|\.bf|\.bg|\.bh|\.bi|\.bj|\.bm|\.bn|\.bo|\.br|\.bs|\.bt|\.bw|\.by|\.bz|\.ca|\.cc|\.cd|\.cf|\.cg|\.ch|\.ci|\.ck|\.cl|\.cm|\.cn|\.co|\.com|\.cr|\.cv|\.cx|\.cy|\.cz|\.de|\.dj|\.dk|\.dm|\.do|\.dz|\.ec|\.edu|\.ee|\.eg|\.es|\.eu|\.fi|\.fj|\.fk|\.fm|\.fo|\.fr|\.ga|\.gd|\.ge|\.gf|\.gg|\.gh|\.gi|\.gl|\.gm|\.gn|\.gov|\.gp|\.gq|\.gr|\.gs|\.gt|\.gu|\.gy|\.hk|\.hm|\.hn|\.hr|\.ht|\.hu|\.id|\.ie|\.il|\.im|\.in|\.io|\.iq|\.is|\.it|\.je|\.jm|\.jo|\.jp|\.ke|\.kg|\.kh|\.ki|\.km|\.kn|\.kr|\.kw|\.ky|\.kz|\.la|\.lb|\.lc|\.li|\.lk|\.lr|\.ls|\.lt|\.lu|\.lv|\.ly|\.ma|\.mc|\.md|\.me|\.mg|\.mil|\.mk|\.ml|\.mm|\.mn|\.mo|\.mobi|\.mp|\.mq|\.mr|\.ms|\.mt|\.mu|\.mv|\.mw|\.mx|\.my|\.na|\.name|\.nc|\.ne|\.net|\.nf|\.ng|\.ni|\.nl|\.no|\.np|\.nr|\.nu|\.nz|\.om|\.org|\.pa|\.pe|\.pf|\.pg|\.ph|\.pk|\.pl|\.pm|\.pn|\.pr|\.pro|\.ps|\.pt|\.py|\.qa|\.re|\.ro|\.rs|\.ru|\.rw|\.sa|\.sb|\.sc|\.se|\.sg|\.sh|\.si|\.sk|\.sl|\.sm|\.sn|\.so|\.sr|\.st|\.su|\.sv|\.sy|\.tc|\.td|\.tf|\.tg|\.th|\.tj|\.tk|\.tl|\.tm|\.tn|\.to|\.tr|\.tt|\.tv|\.tw|\.tz|\.ua|\.ug|\.uk|\.us|\.uy|\.uz|\.vc|\.ve|\.vg|\.vi|\.vn|\.vu|\.wf|\.ws|\.xxx|\.ye|\.yt|\.za|\.zm|\.zw)$").unwrap();
        }

        RE.find(hostname)
            .map(|(b, e)| hostname[b..e].to_string())
            .unwrap_or(hostname.to_string())
    }
}

#[derive(Eq, Debug, Copy, Clone)]
struct RttRecord {
    // lower is prefer
    weight: u64,
    estimated: u32,
    dev: u32,
    last_activity: SystemTime,
}

impl RttRecord {
    fn new() -> RttRecord {
        RttRecord {
            weight: 0,
            estimated: 0,
            dev: 0,
            last_activity: SystemTime::now(),
        }
    }

    fn update_weight(&mut self) {
        self.weight = self.estimated as u64 + 4 * self.dev as u64;
    }

    fn update(&mut self, last_activity: &SystemTime) {
        self.last_activity = last_activity.clone();
        let dt = last_activity.elapsed()
            .map(|d| d.as_secs() as u32 * 1000 + d.subsec_nanos() / 1000000);

        if let Ok(elapsed_ms) = dt {
            let mut estimated = self.estimated as f32;
            let mut dev = self.dev as f32;

            estimated = 0.875 * estimated + 0.125 * elapsed_ms as f32;
            dev = 0.75 * dev + 0.25 * (elapsed_ms as f32 - estimated).abs();

            self.estimated = estimated as u32;
            self.dev = dev as u32;
            self.update_weight();
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
            self.update_weight();
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
