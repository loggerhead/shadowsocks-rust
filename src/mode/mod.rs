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

use config::Config;
use collections::Dict;

macro_rules! err {
    (InvalidMode, $m:expr) => ( io_err!("invalid mode {}", $m) );
    (InvalidPort, $m:expr) => ( io_err!("invalid port {}", $m) );
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Address(pub String, pub u16);
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct Activity(pub Token, pub Address, pub String);
type Servers = Dict<Address, RttRecord>;
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
    servers: Servers,
    host_to_servers: LruCache<String, Servers>,
    activities: Dict<Activity, VecDeque<SystemTime>>,
    token_to_pair: Dict<Token, (Address, String)>,
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
                let port = u16::from_str(parts[1]).map_err(|_| err!(InvalidPort, server))?;
                servers.insert(Address(addr, port), RttRecord::new());
            }
        }

        Ok(ServerChooser {
            rng: thread_rng(),
            mode: mode,
            servers: servers,
            host_to_servers: host_to_servers,
            activities: Dict::default(),
            token_to_pair: Dict::default(),
        })
    }

    pub fn choose(&mut self, hostname: &str) -> Option<Address> {
        match self.mode {
            Mode::Fast => self.choose_by_weight(hostname),
            Mode::Balance => self.random_choose(),
            _ => unreachable!(),
        }
    }

    fn random_choose(&mut self) -> Option<Address> {
        let addr_port_pairs: Vec<&Address> = self.servers.keys().collect();
        let &&Address(ref addr, port) = try_opt!(self.rng.choose(&addr_port_pairs));
        Some(Address(addr.clone(), port))
    }

    fn find_min(servers: &Servers) -> Option<(Address, RttRecord)> {
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
                    if r1 < r2 {
                        server = Some(s);
                        rtt = Some(r1);
                    }
                }
            }
        }

        server.map(|&Address(ref addr, port)| (Address(addr.clone(), port), rtt.unwrap().clone()))
    }

    // TODO: choose server by probability according to its weight
    // the compute need O(n) time. But for normal user,
    // the servers number is small, so the compute time is acceptable
    fn choose_by_weight(&mut self, hostname: &str) -> Option<Address> {
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

    pub fn record(&mut self, token: Token, server: Address, hostname: &str) {
        match self.mode {
            Mode::Fast => {
                self.token_to_pair.insert(token, (server.clone(), hostname.to_string()));
                let host = self.get_host(hostname);
                let times =
                    self.activities.entry(Activity(token, server, host)).or_insert(VecDeque::new());
                times.push_back(SystemTime::now());
            }
            _ => {}
        }
    }

    pub fn update(&mut self, token: Token, server: Address, hostname: &str) {
        match self.mode {
            Mode::Fast => {
                let host = self.get_host(hostname);
                let tsh = Activity(token, server, host);
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

    pub fn punish(&mut self, token: Token) {
        match self.mode {
            Mode::Fast => {
                if let Some(&(ref server, ref hostname)) = self.token_to_pair.get(&token) {
                    let host = self.get_host(hostname);
                    let tsh = Activity(token, server.clone(), host);
                    self.activities.remove(&tsh);
                    self.host_to_servers.get_mut(&tsh.2).map(|servers| {
                        servers.get_mut(&tsh.1).map(|record| {
                            record.punish();
                        });
                    });
                }
            }
            _ => {}
        }
    }

    fn get_host(&self, hostname: &str) -> String {
        lazy_static! {
            static ref RE: Regex = Regex::new(concat!(r"[A-Za-z\d-]+(\.ne\.jp|\.net\.ck|\.net\.cm",
                                                      r"|\.net\.in|\.og\.ao|\.or\.th|\.org\.ck",
                                                      r"|\.org\.cn|\.org\.ls|\.com\.af|\.com\.ag",
                                                      r"|\.com\.ai|\.com\.al|\.com\.ar|\.com\.au",
                                                      r"|\.com\.aw|\.com\.az|\.com\.bb|\.com\.bd",
                                                      r"|\.com\.bh|\.com\.bi|\.com\.bm|\.com\.bn",
                                                      r"|\.com\.bo|\.com\.br|\.com\.bs|\.com\.bt",
                                                      r"|\.com\.by|\.com\.bz|\.com\.cm|\.com\.cn",
                                                      r"|\.com\.co|\.com\.cu|\.com\.cv|\.com\.cy",
                                                      r"|\.com\.do|\.com\.dz|\.com\.ec|\.com\.ee",
                                                      r"|\.com\.eg|\.com\.es|\.com\.et|\.com\.fj",
                                                      r"|\.com\.ge|\.com\.gh|\.com\.gi|\.com\.gl",
                                                      r"|\.com\.gn|\.com\.gp|\.com\.gr|\.com\.gt",
                                                      r"|\.com\.gu|\.com\.hk|\.com\.hn|\.com\.hr",
                                                      r"|\.com\.ht|\.com\.jm|\.com\.jo|\.com\.kg",
                                                      r"|\.com\.kh|\.com\.ki|\.com\.kw|\.com\.ky",
                                                      r"|\.com\.kz|\.com\.lb|\.com\.lc|\.com\.lk",
                                                      r"|\.com\.lr|\.com\.lv|\.com\.ly|\.com\.mg",
                                                      r"|\.com\.mk|\.com\.mm|\.com\.mo|\.com\.mt",
                                                      r"|\.com\.mu|\.com\.mv|\.com\.mw|\.com\.mx",
                                                      r"|\.com\.my|\.com\.na|\.com\.nf|\.com\.ng",
                                                      r"|\.com\.ni|\.com\.np|\.com\.nr|\.com\.om",
                                                      r"|\.com\.pa|\.com\.pe|\.com\.pg|\.com\.ph",
                                                      r"|\.com\.pk|\.com\.pl|\.com\.pr|\.com\.ps",
                                                      r"|\.com\.pt|\.com\.py|\.com\.qa|\.com\.ro",
                                                      r"|\.com\.sa|\.com\.sb|\.com\.sc|\.com\.sg",
                                                      r"|\.com\.sl|\.com\.sn|\.com\.sv|\.com\.sy",
                                                      r"|\.com\.tj|\.com\.tn|\.com\.tr|\.com\.tt",
                                                      r"|\.com\.tw|\.com\.ua|\.com\.uy|\.com\.uz",
                                                      r"|\.com\.vc|\.com\.ve|\.com\.vi|\.com\.vn",
                                                      r"|\.com\.ye|\.co\.ao|\.co\.ba|\.co\.bw",
                                                      r"|\.co\.cc|\.co\.ck|\.co\.cr|\.co\.fk",
                                                      r"|\.co\.id|\.co\.il|\.co\.im|\.co\.in",
                                                      r"|\.co\.jp|\.co\.ke|\.co\.kr|\.co\.ls",
                                                      r"|\.co\.ma|\.co\.mz|\.co\.nl|\.co\.nz",
                                                      r"|\.co\.th|\.co\.tz|\.co\.ug|\.co\.uk",
                                                      r"|\.co\.uz|\.co\.ve|\.co\.vi|\.co\.za",
                                                      r"|\.co\.zm|\.co\.zw|\.ac|\.ad|\.ae|\.af",
                                                      r"|\.ag|\.ai|\.al|\.am|\.ao|\.aq|\.ar|\.as",
                                                      r"|\.asia|\.at|\.au|\.aw|\.ax|\.az|\.ba|\.bb",
                                                      r"|\.bd|\.be|\.bf|\.bg|\.bh|\.bi|\.bj|\.bm",
                                                      r"|\.bn|\.bo|\.br|\.bs|\.bt|\.bw|\.by|\.bz",
                                                      r"|\.ca|\.cc|\.cd|\.cf|\.cg|\.ch|\.ci|\.ck",
                                                      r"|\.cl|\.cm|\.cn|\.co|\.com|\.cr|\.cv|\.cx",
                                                      r"|\.cy|\.cz|\.de|\.dj|\.dk|\.dm|\.do|\.dz",
                                                      r"|\.ec|\.edu|\.ee|\.eg|\.es|\.eu|\.fi|\.fj",
                                                      r"|\.fk|\.fm|\.fo|\.fr|\.ga|\.gd|\.ge|\.gf",
                                                      r"|\.gg|\.gh|\.gi|\.gl|\.gm|\.gn|\.gov|\.gp",
                                                      r"|\.gq|\.gr|\.gs|\.gt|\.gu|\.gy|\.hk|\.hm",
                                                      r"|\.hn|\.hr|\.ht|\.hu|\.id|\.ie|\.il|\.im",
                                                      r"|\.in|\.io|\.iq|\.is|\.it|\.je|\.jm|\.jo",
                                                      r"|\.jp|\.ke|\.kg|\.kh|\.ki|\.km|\.kn|\.kr",
                                                      r"|\.kw|\.ky|\.kz|\.la|\.lb|\.lc|\.li|\.lk",
                                                      r"|\.lr|\.ls|\.lt|\.lu|\.lv|\.ly|\.ma|\.mc",
                                                      r"|\.md|\.me|\.mg|\.mil|\.mk|\.ml|\.mm|\.mn",
                                                      r"|\.mo|\.mobi|\.mp|\.mq|\.mr|\.ms|\.mt|\.mu",
                                                      r"|\.mv|\.mw|\.mx|\.my|\.na|\.name|\.nc|\.ne",
                                                      r"|\.net|\.nf|\.ng|\.ni|\.nl|\.no|\.np|\.nr",
                                                      r"|\.nu|\.nz|\.om|\.org|\.pa|\.pe|\.pf|\.pg",
                                                      r"|\.ph|\.pk|\.pl|\.pm|\.pn|\.pr|\.pro|\.ps",
                                                      r"|\.pt|\.py|\.qa|\.re|\.ro|\.rs|\.ru|\.rw",
                                                      r"|\.sa|\.sb|\.sc|\.se|\.sg|\.sh|\.si|\.sk",
                                                      r"|\.sl|\.sm|\.sn|\.so|\.sr|\.st|\.su|\.sv",
                                                      r"|\.sy|\.tc|\.td|\.tf|\.tg|\.th|\.tj|\.tk",
                                                      r"|\.tl|\.tm|\.tn|\.to|\.tr|\.tt|\.tv|\.tw",
                                                      r"|\.tz|\.ua|\.ug|\.uk|\.us|\.uy|\.uz|\.vc",
                                                      r"|\.ve|\.vg|\.vi|\.vn|\.vu|\.wf|\.ws|\.xxx",
                                                      r"|\.ye|\.yt|\.za|\.zm|\.zw)$")).unwrap();
        }

        RE.find(hostname)
            .map(|(b, e)| hostname[b..e].to_string())
            .unwrap_or(hostname.to_string())
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
