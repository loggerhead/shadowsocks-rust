use std::env;
use std::str;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::iter::FromIterator;
use std::ops::{Index, IndexMut};
use std::collections::hash_set::Iter;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, BuildHasherDefault};

use mio::Token;
use rand::random;
use fnv::FnvHasher;
use chrono::{Local};
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
        &Some((ref host, port)) => format!("{}:{}", host, port),
        _ => format!("None"),
    }
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

impl<K, V> Dict<K, V> where K: Hash + Eq {
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
        self.map.contains_key(k)
    }

    pub fn del(&mut self, k: &K) -> Option<V> {
        self.map.remove(k)
    }
}

impl<K, V> Index<K> for Dict<K, V> where K: Hash + Eq {
    type Output = V;

    fn index(&self, index: K) -> &V {
        self.get(&index).expect("invalid index")
    }
}

impl<K, V> IndexMut<K> for Dict<K, V> where K: Hash + Eq {
    fn index_mut(&mut self, index: K) -> &mut V {
        self.get_mut(&index).expect("invalid index")
    }
}


pub struct Set<T> {
    items: HashSet<T, BuildHasherDefault<FnvHasher>>,
}

impl<T> Set<T> where T: Hash + Eq {
    pub fn new() -> Self {
        Set {
            items: HashSet::default(),
        }
    }

    pub fn from_vec(items: Vec<T>) -> Self {
        Set {
            items: HashSet::from_iter(items),
        }
    }

    pub fn has(&self, t: &T) -> bool {
        self.items.contains(t)
    }

    pub fn add(&mut self, t: T) {
        self.items.insert(t);
    }

    pub fn del(&mut self, t: &T) -> bool {
        self.items.remove(t)
    }

    pub fn iter(&self) -> Iter<T> {
        self.items.iter()
    }

    pub fn to_vec(self) -> Vec<T> {
        self.items.into_iter().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}


const MAX_RAND_RETRY_TIMES: usize = 1000;

pub struct Holder<T> {
    items: Dict<Token, T>,
    exclusions: Set<Token>,
}

impl<T> Holder<T> {
    pub fn new() -> Holder<T> {
        Holder {
            items: Dict::new(),
            exclusions: Set::new(),
        }
    }

    pub fn new_exclude_from(exclusions: Vec<Token>) -> Holder<T> {
        Holder {
            items: Dict::new(),
            exclusions: Set::from_vec(exclusions),
        }
    }

    pub fn has(&self, token: Token) -> bool {
        self.items.has(&token)
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
        while self.exclusions.has(&token) {
            token = Token(random::<usize>());

            i += 1;
            if i > MAX_RAND_RETRY_TIMES {
                return None;
            }
        }

        self.items.put(token, v);
        self.exclusions.add(token);
        Some(token)
    }

    pub fn del(&mut self, token: Token) -> Option<T> {
        self.exclusions.del(&token);
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
