use std::io::Cursor;
use std::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, AddrParseError};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

#[allow(non_camel_case_types)]
pub enum AddressFamily {
    AF_INET,
    AF_INET6
}

pub fn get_address_family(address: &str) -> Option<AddressFamily> {
    if str2addr4(&format!("{}:0", address)).is_some() {
        return Some(AddressFamily::AF_INET);
    }

    match str2addr6(&format!("{}", address)) {
        Some(_) => Some(AddressFamily::AF_INET6),
        _ => None,
    }
}

pub fn is_ip(address: &str) -> bool {
    get_address_family(address).is_some()
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

// TODO: consider change to return Result
pub fn slice2ip4(data: &[u8]) -> String {
    assert!(data.len() >= 4);
    format!("{}", Ipv4Addr::from(slice2sized!(data, 4)))
}

pub fn slice2ip6(data: &[u8]) -> String {
    assert!(data.len() >= 16);
    format!("{}", Ipv6Addr::from(slice2sized!(data, 16)))
}

pub fn str2addr4(ip: &str) -> Option<SocketAddrV4> {
    SocketAddrV4::from_str(ip).ok()
}

pub fn str2addr6(ip: &str) -> Option<SocketAddrV6> {
    SocketAddrV6::from_str(ip).ok()
}

pub fn pair2socket_addr(ip: &str, port: u16) -> Result<SocketAddr, AddrParseError> {
    Ipv4Addr::from_str(ip).map(|ip| {
        SocketAddr::new(IpAddr::V4(ip), port)
    })
}


pub trait NetworkWriteBytes: WriteBytesExt {
    fn put_u8(&mut self, num: u8) -> Option<()> {
        self.write_u8(num).ok()
    }

    fn put_u16(&mut self, num: u16) -> Option<()> {
        self.write_u16::<NetworkEndian>(num).ok()
    }
}

impl NetworkWriteBytes for Vec<u8> { }

pub trait NetworkReadBytes: ReadBytesExt {
    fn get_u8(&mut self) -> Option<u8> {
        self.read_u8().ok()
    }

    fn get_u16(&mut self) -> Option<u16> {
        self.read_u16::<NetworkEndian>().ok()
    }

    fn get_u32(&mut self) -> Option<u32> {
        self.read_u32::<NetworkEndian>().ok()
    }
}

impl<'a> NetworkReadBytes for Cursor<&'a [u8]> { }
impl<'a> NetworkReadBytes for Cursor<&'a Vec<u8>> { }

impl<'a> NetworkReadBytes for &'a [u8] {
    fn get_u8(&mut self) -> Option<u8> {
        Cursor::new(self).read_u8().ok()
    }

    fn get_u16(&mut self) -> Option<u16> {
        Cursor::new(self).read_u16::<NetworkEndian>().ok()
    }

    fn get_u32(&mut self) -> Option<u32> {
        Cursor::new(self).read_u32::<NetworkEndian>().ok()
    }
}
