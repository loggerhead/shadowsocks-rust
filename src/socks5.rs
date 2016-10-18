use std::net::IpAddr;
use network::{slice2ip4, slice2ip6, NetworkReadBytes};

/// (addr_type, dest_addr, dest_port, header_length)
pub type Socks5Header = (u8, String, u16, usize);

#[derive(Debug, PartialEq)]
pub enum CheckAuthResult {
    Success,
    BadSocksHeader,
    NoAcceptableMethods,
}

// +------+----------+----------+----------+
// | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +------+----------+----------+----------+
// |  1   | Variable |    2     | Variable |
// +------+----------+----------+----------+
pub fn parse_header(data: &[u8]) -> Option<Socks5Header> {
    let addr_type = data[0];
    let mut dest_addr = None;
    let mut dest_port = 0;
    let mut header_len = 0;

    match addr_type & addr_type::MASK {
        addr_type::IPV4 => {
            if data.len() >= 7 {
                dest_addr = slice2ip4(&data[1..5]);
                dest_port = (&data[5..7]).get_u16().unwrap();
                header_len = 7;
            } else {
                warn!("header is too short");
            }
        }
        addr_type::IPV6 => {
            if data.len() >= 19 {
                dest_addr = slice2ip6(&data[1..17]);
                dest_port = (&data[17..19]).get_u16().unwrap();
                header_len = 19;
            } else {
                warn!("header is too short");
            }
        }
        addr_type::HOST => {
            if data.len() >= 2 {
                let addr_len = data[1] as usize;
                if data.len() >= 4 + addr_len {
                    dest_addr = match String::from_utf8(Vec::from(&data[2..2 + addr_len])) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            warn!("not a valid UTF-8 string: {}", e);
                            None
                        }
                    };
                    dest_port = (&data[2 + addr_len..4 + addr_len]).get_u16().unwrap();
                    header_len = 4 + addr_len;
                } else {
                    warn!("header is too short");
                }
            } else {
                warn!("header is too short");
            }
        }
        _ => {
            warn!("unsupported addrtype {}, maybe wrong password or encryption method",
                  addr_type)
        }
    }

    dest_addr.and_then(|dest_addr| Some((addr_type, dest_addr, dest_port, header_len)))
}

pub fn check_auth_method(data: &[u8]) -> CheckAuthResult {
    if data.len() < 3 {
        warn!("method selection header too short");
        return CheckAuthResult::BadSocksHeader;
    }

    let socks_version = data[0];
    if socks_version != 5 {
        warn!("unsupported SOCKS protocol version {}", socks_version);
        return CheckAuthResult::BadSocksHeader;
    }

    let nmethods = data[1];
    if nmethods < 1 || data.len() as u8 != nmethods + 2 {
        warn!("NMETHODS and number of METHODS mismatch");
        return CheckAuthResult::BadSocksHeader;
    }

    let mut noauto_exist = false;
    for method in &data[2..] {
        if *method == method::NOAUTH {
            noauto_exist = true;
            break;
        }
    }

    if noauto_exist {
        CheckAuthResult::Success
    } else {
        warn!("none of socks method's requested by client is supported");
        CheckAuthResult::NoAcceptableMethods
    }
}

pub fn pack_addr(ip: IpAddr) -> Vec<u8> {
    let mut res = Vec::with_capacity(17);
    match ip {
        IpAddr::V4(ip) => {
            res.push(0x01);
            res.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            res.push(0x04);
            res.extend_from_slice(&ip.octets());
        }
    }
    res
}

#[allow(dead_code, non_snake_case)]
pub mod addr_type {
    pub const IPV4: u8 = 0x01;
    pub const IPV6: u8 = 0x04;
    pub const HOST: u8 = 0x03;
    pub const AUTH: u8 = 0x10;
    pub const MASK: u8 = 0xF;
}

// SOCKS method definition
#[allow(dead_code, non_snake_case)]
pub mod method {
    pub const NOAUTH: u8 = 0;
    pub const GSSAPI: u8 = 1;
    pub const USER_PASS: u8 = 2;
}

// SOCKS command definition
#[allow(dead_code, non_snake_case)]
pub mod cmd {
    pub const CONNECT: u8 = 1;
    pub const BIND: u8 = 2;
    pub const UDP_ASSOCIATE: u8 = 3;
}
