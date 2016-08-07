use network::NetworkReadBytes;

pub const ADDRTYPE_IPV4: u8 = 0x01;
pub const ADDRTYPE_IPV6: u8 = 0x04;
pub const ADDRTYPE_HOST: u8 = 0x03;
pub const ADDRTYPE_AUTH: u8 = 0x10;
pub const ADDRTYPE_MASK: u8 = 0xF;

pub fn parse_header(data: &[u8]) -> Option<(u8, &[u8], u16, usize)> {
    let addr_type = data[0];
    let mut dest_addr: &[u8] = &[];
    let mut dest_port = 0;
    let mut header_len = 0;

    match addr_type & ADDRTYPE_MASK {
        ADDRTYPE_IPV4 => {
            if data.len() >= 7 {
                dest_addr = &data[1..5];
                dest_port = (&data[5..7]).get_u16().unwrap();
                header_len = 7;
            } else {
                warn!("header is too short");
            }
        }
        ADDRTYPE_IPV6 => {
            if data.len() >= 19 {
                dest_addr = &data[1..17];
                dest_port = (&data[17..19]).get_u16().unwrap();
                header_len = 19;
            } else {
                warn!("header is too short");
            }
        }
        ADDRTYPE_HOST => {
            if data.len() >= 2 {
                let addr_len = data[1] as usize;
                if data.len() >= 4 + addr_len {
                    dest_addr = &data[2..2 + addr_len];
                    dest_port = (&data[2 + addr_len..4 + addr_len]).get_u16().unwrap();
                    header_len = 4 + addr_len;
                } else {
                    warn!("header is too short");
                }
            } else {
                warn!("header is too short");
            }
        }
        _ => warn!("unsupported addrtype {}, maybe wrong password or encryption method",
                   addr_type),
    }

    if dest_addr.len() > 0 {
        Some((addr_type, dest_addr, dest_port, header_len))
    } else {
        None
    }
}
