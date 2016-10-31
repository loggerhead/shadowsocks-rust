use std::io::Cursor;
use std::str::FromStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, AddrParseError};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use mio::udp::UdpSocket;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

#[allow(non_camel_case_types)]
pub enum AddressFamily {
    AF_INET,
    AF_INET6,
}

pub fn alloc_udp_socket() -> Option<UdpSocket> {
    match UdpSocket::v4() {
        Ok(sock) => Some(sock),
        Err(e) => {
            error!("cannot alloc a UDP socket: {}", e);
            None
        }
    }
}

pub fn get_address_family(address: &str) -> Option<AddressFamily> {
    if str2addr4(&format!("{}:0", address)).is_some() {
        return Some(AddressFamily::AF_INET);
    }

    if str2addr6(address).is_some() {
        return Some(AddressFamily::AF_INET6);
    }

    None
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

pub fn str2addr4(ip: &str) -> Option<SocketAddr> {
    let addr = try_opt!(SocketAddrV4::from_str(ip).ok());
    Some(SocketAddr::V4(addr))
}

pub fn str2addr6(ip: &str) -> Option<SocketAddr> {
    let addr = try_opt!(SocketAddrV6::from_str(ip).ok());
    Some(SocketAddr::V6(addr))
}

pub fn pair2socket_addr(ip: &str, port: u16) -> Result<SocketAddr, AddrParseError> {
    Ipv4Addr::from_str(ip).map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
}


pub trait NetworkWriteBytes: WriteBytesExt {
    fn put_u8(&mut self, num: u8) -> Option<()> {
        self.write_u8(num).ok()
    }

    fn put_u16(&mut self, num: u16) -> Option<()> {
        self.write_u16::<NetworkEndian>(num).ok()
    }

    fn put_i32(&mut self, num: i32) -> Option<()> {
        self.write_i32::<NetworkEndian>(num).ok()
    }
}

impl NetworkWriteBytes for Vec<u8> {}

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

impl<'a> NetworkReadBytes for Cursor<&'a [u8]> {}
impl<'a> NetworkReadBytes for Cursor<&'a Vec<u8>> {}

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

#[macro_export]
macro_rules! pack {
    (u16, $r:expr, $v:expr) => ( try_opt!($r.put_u16($v)); );
    (u8, $r:expr, $v:expr) => ( try_opt!($r.put_u8($v)); );
}

#[macro_export]
macro_rules! unpack {
    (u16, $r:expr) => ( try_opt!($r.get_u16()); );
    (u8, $r:expr) => ( try_opt!($r.get_u8()); );
}
