use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::path::Path;
use std::rc::Rc;
use std::cell::RefCell;
pub use std::io::{Result, Error};

#[macro_export]
macro_rules! err_from {
    ($e:expr) => { Err(From::from($e)) }
}

#[macro_export]
macro_rules! create_from_for_error {
    ($err:tt) => (
        impl From<$err> for io::Error {
            fn from(e: $err) -> io::Error {
                io::Error::new(io::ErrorKind::Other, e)
            }
        }
    )
}

#[macro_export]
macro_rules! vec2unsafe_slice {
    (let $name:ident = $v:expr) => (
        use std::slice::from_raw_parts_mut;

        let ptr = $v.as_mut_ptr();
        let cap = $v.capacity();
        let raw = unsafe { &mut from_raw_parts_mut(ptr, cap) };
        let $name = raw;
        unsafe { $v.set_len(0); }
    );
}

pub fn handle_every_line<P: AsRef<Path>>(filepath: P, func: &mut FnMut(String)) -> Result<()> {
    let f = File::open(filepath)?;
    let reader = BufReader::new(f);
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line.trim().to_string(),
            _ => break,
        };

        func(line);
    }
    Ok(())
}

pub fn shift_vec<T: Clone>(v: &mut Vec<T>, offset: usize) {
    let remain = v.len() - offset;
    for i in 0..remain {
        v[i] = v[i + offset].clone();
    }
    unsafe {
        v.set_len(remain);
    }
}

pub type RcCell<T> = Rc<RefCell<T>>;

#[inline]
pub fn new_rc_cell<T>(val: T) -> RcCell<T> {
    Rc::new(RefCell::new(val))
}
