use std::env;
use std::str;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::iter::FromIterator;
use std::ops::{Index, IndexMut};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, BuildHasherDefault};

use rand::random;
use fnv::FnvHasher;
use chrono::{Local};
use mio::{Token, EventSet};
use env_logger::LogBuilder;
use log::{LogRecord, LogLevelFilter};


pub fn init_env_logger() {
    let format = |record: &LogRecord| {
        let dt = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        format!("{} - {:5} - {}", dt, record.level(), record.args())
    };

    let mut builder = LogBuilder::new();
    builder.format(format).filter(None, LogLevelFilter::Info);

    if env::var("RUST_LOG").is_ok() {
       builder.parse(&env::var("RUST_LOG").unwrap());
    }

    builder.init().unwrap();
}

pub fn address2str(address: &Option<(String, u16)>) -> String {
    match address {
        &Some((ref host, port)) => {
            format!("{}:{}", host, port)
        }
        _ => {
            format!("None")
        }
    }
}

pub fn get_basic_events() -> EventSet {
    EventSet::readable() | EventSet::error()
}

pub fn slice2str(data: &[u8]) -> Option<&str> {
    str::from_utf8(data).ok()
}

pub fn slice2string(data: &[u8]) -> Option<String> {
    String::from_utf8(data.to_vec()).ok()
}

pub fn handle_every_line(filepath: &str, func: &mut FnMut(String)) {
    if let Ok(f) = File::open(filepath) {
        let reader = BufReader::new(f);
        for line in reader.lines() {
            let line = match line {
                Ok(line) => line.trim().to_string(),
                _ => break,
            };

            func(line);
        }
    }
}


pub struct Dict<K, V> {
    map: HashMap<K, V, BuildHasherDefault<FnvHasher>>
}

impl<K, V> Dict<K, V>
    where K: Hash + Eq
{
    pub fn new() -> Self {
        Dict {
            map: HashMap::default()
        }
    }

    pub fn put(&mut self, k: K, v: V) {
        self.map.insert(k, v);
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k)
    }

    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        self.map.get_mut(k)
    }

    pub fn has(&self, k: &K) -> bool {
        self.get(k).is_some()
    }

    pub fn del(&mut self, k: &K) -> Option<V> {
        self.map.remove(k)
    }
}

impl<K, V> Index<K> for Dict<K, V>
    where K: Hash + Eq
{
    type Output = V;

    fn index(&self, index: K) -> &V {
        self.get(&index).expect("invalid index")
    }
}

impl<K, V> IndexMut<K> for Dict<K, V>
    where K: Hash + Eq
{
    fn index_mut(&mut self, index: K) -> &mut V {
        self.get_mut(&index).expect("invalid index")
    }
}

const MAX_RAND_RETRY_TIMES: usize = 1000;

pub struct Holder<T> {
    items: Dict<Token, T>,
    exclusions: HashSet<Token, BuildHasherDefault<FnvHasher>>,
}

impl<T> Holder<T> {
    pub fn new() -> Holder<T> {
        Holder {
            items: Dict::new(),
            exclusions: HashSet::default(),
        }
    }

    pub fn new_exclude_from(exclusions: Vec<Token>) -> Holder<T> {
        Holder {
            items: Dict::new(),
            exclusions: HashSet::from_iter(exclusions),
        }
    }

    pub fn get(&self, token: Token) -> Option<&T> {
        self.items.get(&token)
    }

    pub fn get_mut(&mut self, token: Token) -> Option<&mut T> {
        self.items.get_mut(&token)
    }

    pub fn add(&mut self, v: T) -> Option<Token> {
        let mut i = 0;
        let mut token = Token(random::<usize>());
        while self.exclusions.contains(&token) {
            token = Token(random::<usize>());

            i += 1;
            if i > MAX_RAND_RETRY_TIMES {
                return None;
            }
        }

        self.items.put(token, v);
        self.exclusions.insert(token);

        Some(token)
    }

    pub fn del(&mut self, token: Token) -> Option<T> {
        self.exclusions.remove(&token);

        self.items.del(&token)
    }
}

impl<T> Index<Token> for Holder<T> {
    type Output = T;

    fn index(&self, index: Token) -> &T {
        match self.get(index) {
            Some(v) => v,
            _ => panic!("invalid index: {:?}", index),
        }
    }
}

impl<T> IndexMut<Token> for Holder<T> {
    fn index_mut(&mut self, index: Token) -> &mut T {
        match self.get_mut(index) {
            Some(v) => v,
            _ => panic!("invalid index: {:?}", index),
        }
    }
}
