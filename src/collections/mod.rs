pub use self::holder::Holder;

mod holder;

use std::hash::BuildHasherDefault;
use std::collections::{HashSet, HashMap};

use fnv::FnvHasher;

pub type Set<T> = HashSet<T, BuildHasherDefault<FnvHasher>>;
pub type Dict<K, V> = HashMap<K, V, BuildHasherDefault<FnvHasher>>;
