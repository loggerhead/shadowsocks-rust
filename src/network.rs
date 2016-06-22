use std::io::Cursor;
use std::str::FromStr;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};


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


pub enum AddressFamily {
    AF_INET,
    AF_INET6
}

pub fn get_address_family(address: &str) -> Option<AddressFamily> {
    match SocketAddrV4::from_str(&format!("{}:0", address)) {
        Ok(_) => return Some(AddressFamily::AF_INET),
        _ => {},
    }

    match SocketAddrV6::from_str(&format!("{}", address)) {
        Ok(_) => return Some(AddressFamily::AF_INET6),
        _ => return None,
    }
}
