use std::ops::{Index, IndexMut};
use std::hash::{Hash, BuildHasherDefault};
use std::collections::{HashMap, hash_map};

use fnv::FnvHasher;

pub struct Dict<K, V> {
    map: HashMap<K, V, BuildHasherDefault<FnvHasher>>,
}

impl<K, V> Dict<K, V>
    where K: Hash + Eq
{
    pub fn new() -> Self {
        Dict { map: HashMap::default() }
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

    pub fn clear(&mut self) {
        self.map.clear()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn values(&self) -> hash_map::Values<K, V> {
        self.map.values()
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
