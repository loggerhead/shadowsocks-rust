use std::io;
use std::io::Cursor;
use std::convert::From;
use std::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

use error::{SocketError, Result};

#[allow(non_camel_case_types)]
pub enum AddressFamily {
    AF_INET,
    AF_INET6,
}

pub fn is_ipv4(ip: &str) -> bool {
    Ipv4Addr::from_str(ip).is_ok()
}

pub fn is_ipv6(ip: &str) -> bool {
    Ipv6Addr::from_str(ip).is_ok()
}

pub fn is_ip(ip: &str) -> bool {
    is_ipv4(ip) || is_ipv6(ip)
}

macro_rules! slice2sized {
    ($bytes:expr, $l: expr) => (
        {
            let mut arr = [0u8; $l];
            for i in 0..$bytes.len() {
                arr[i] = $bytes[i];
            }

            arr
        }
    )
}

pub fn slice2ip4(data: &[u8]) -> Option<String> {
    if data.len() >= 4 {
        Some(format!("{}", Ipv4Addr::from(slice2sized!(data, 4))))
    } else {
        None
    }
}

pub fn slice2ip6(data: &[u8]) -> Option<String> {
    if data.len() >= 16 {
        Some(format!("{}", Ipv6Addr::from(slice2sized!(data, 16))))
    } else {
        None
    }
}

pub fn pair2addr4(ip: &str, port: u16) -> Option<SocketAddr> {
    Ipv4Addr::from_str(ip).map(|ip| SocketAddr::new(IpAddr::V4(ip), port)).ok()
}

pub fn pair2addr6(ip: &str, port: u16) -> Option<SocketAddr> {
    Ipv6Addr::from_str(ip).map(|ip| SocketAddr::new(IpAddr::V6(ip), port)).ok()
}

pub fn pair2addr(ip: &str, port: u16) -> Result<SocketAddr> {
    let res = match pair2addr4(ip, port) {
        None => pair2addr6(ip, port),
        addr => addr,
    };
    res.ok_or(From::from(SocketError::ParseAddrFailed(format!("{}:{}", ip, port))))
}

pub trait NetworkWriteBytes: WriteBytesExt {
    fn put_u8(&mut self, num: u8) -> io::Result<()> {
        self.write_u8(num)
    }

    fn put_u16(&mut self, num: u16) -> io::Result<()> {
        self.write_u16::<NetworkEndian>(num)
    }

    fn put_i32(&mut self, num: i32) -> io::Result<()> {
        self.write_i32::<NetworkEndian>(num)
    }
}

impl NetworkWriteBytes for Vec<u8> {}

pub trait NetworkReadBytes: ReadBytesExt {
    fn get_u8(&mut self) -> io::Result<u8> {
        self.read_u8()
    }

    fn get_u16(&mut self) -> io::Result<u16> {
        self.read_u16::<NetworkEndian>()
    }

    fn get_u32(&mut self) -> io::Result<u32> {
        self.read_u32::<NetworkEndian>()
    }
}

impl<'a> NetworkReadBytes for Cursor<&'a [u8]> {}
impl<'a> NetworkReadBytes for Cursor<&'a Vec<u8>> {}

impl<'a> NetworkReadBytes for &'a [u8] {
    fn get_u8(&mut self) -> io::Result<u8> {
        Cursor::new(self).read_u8()
    }

    fn get_u16(&mut self) -> io::Result<u16> {
        Cursor::new(self).read_u16::<NetworkEndian>()
    }

    fn get_u32(&mut self) -> io::Result<u32> {
        Cursor::new(self).read_u32::<NetworkEndian>()
    }
}

#[macro_export]
macro_rules! pack {
    (i32, $r:expr, $v:expr) => ( try_opt!($r.put_i32($v).ok()); );
    (u16, $r:expr, $v:expr) => ( try_opt!($r.put_u16($v).ok()); );
    (u8, $r:expr, $v:expr) => ( try_opt!($r.put_u8($v).ok()); );
}

#[macro_export]
macro_rules! unpack {
    (u32, $r:expr) => ( try_opt!($r.get_u32().ok()); );
    (u16, $r:expr) => ( try_opt!($r.get_u16().ok()); );
    (u8, $r:expr) => ( try_opt!($r.get_u8().ok()); );
}

#[macro_export]
macro_rules! try_pack {
    (i32, $r:expr, $v:expr) => ( try!($r.put_i32($v)); );
    (u16, $r:expr, $v:expr) => ( try!($r.put_u16($v)); );
    (u8, $r:expr, $v:expr) => ( try!($r.put_u8($v)); );
}

#[macro_export]
macro_rules! try_unpack {
    (u32, $r:expr) => ( try!($r.get_u32()); );
    (u16, $r:expr) => ( try!($r.get_u16()); );
    (u8, $r:expr) => ( try!($r.get_u8()); );
}
