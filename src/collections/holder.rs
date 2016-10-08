use std::ops::{Index, IndexMut};

use mio::Token;
use rand::random;

use super::set::Set;
use super::dict::Dict;

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

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
