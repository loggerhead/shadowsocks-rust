use std::borrow::Borrow;
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

    pub fn get<Q: ?Sized>(&self, k: &Q) -> Option<&V>
        where K: Borrow<Q>,
              Q: Hash + Eq {
        self.map.get(k)
    }

    pub fn get_mut<Q: ?Sized>(&mut self, k: &Q) -> Option<&mut V>
        where K: Borrow<Q>,
              Q: Hash + Eq {
        self.map.get_mut(k)
    }

    pub fn has<Q: ?Sized>(&self, k: &Q) -> bool
        where K: Borrow<Q>,
              Q: Hash + Eq {
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

impl<'a, K, Q: ?Sized, V> Index<&'a Q> for Dict<K, V>
    where K: Eq + Hash + Borrow<Q>,
          Q: Eq + Hash
{
    type Output = V;

    #[inline]
    fn index(&self, index: &Q) -> &V {
        self.get(index).expect("invalid index")
    }
}

impl<'a, K, Q: ?Sized, V> IndexMut<&'a Q> for Dict<K, V>
    where K: Eq + Hash + Borrow<Q>,
          Q: Eq + Hash
{
    #[inline]
    fn index_mut(&mut self, index: &Q) -> &mut V {
        self.get_mut(index).expect("invalid index")
    }
}
