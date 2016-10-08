use std::iter::FromIterator;
use std::hash::{Hash, BuildHasherDefault};
use std::collections::{HashSet, hash_set};

use fnv::FnvHasher;

pub struct Set<T> {
    items: HashSet<T, BuildHasherDefault<FnvHasher>>,
}

impl<T> Set<T>
    where T: Hash + Eq
{
    pub fn new() -> Self {
        Set { items: HashSet::default() }
    }

    pub fn from_vec(items: Vec<T>) -> Self {
        Set { items: HashSet::from_iter(items) }
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

    pub fn iter(&self) -> hash_set::Iter<T> {
        self.items.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
