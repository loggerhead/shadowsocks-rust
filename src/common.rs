pub const ADDRTYPE_IPV4: u8 = 0x01;
pub const ADDRTYPE_IPV6: u8 = 0x04;
pub const ADDRTYPE_HOST: u8 = 0x03;
pub const ADDRTYPE_AUTH: u8 = 0x10;
pub const ADDRTYPE_MASK: u8 = 0xF;

pub fn parse_header(data: &[u8]) -> Option<(u8, &[u8], u16, usize)> {
    unimplemented!()
}
