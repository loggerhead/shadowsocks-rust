use std::str;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::rc::Rc;
use std::cell::RefCell;

macro_rules! io_err {
    ($desc:expr) => ( io::Error::new(io::ErrorKind::Other, $desc) );
    ($fmt:expr, $($arg:tt)*) => ( io::Error::new(io::ErrorKind::Other, format!($fmt, $($arg)*)) );
}

macro_rules! new_fat_slice_from_vec {
    ($name:ident, $v:expr) => (
        use std::slice::from_raw_parts_mut;

        let ptr = $v.as_mut_ptr();
        let cap = $v.capacity();
        let raw = unsafe { &mut from_raw_parts_mut(ptr, cap) };
        let $name = raw;
        unsafe { $v.set_len(0); }
    );
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

pub fn new_rc_cell<T>(val: T) -> RcCell<T> {
    Rc::new(RefCell::new(val))
}
