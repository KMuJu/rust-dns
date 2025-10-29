use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn bytes_to_ip(ip: &[u8]) -> Option<IpAddr> {
    match ip.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))),
        16 => Some(IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([ip[0], ip[1]]),
            u16::from_be_bytes([ip[2], ip[3]]),
            u16::from_be_bytes([ip[4], ip[5]]),
            u16::from_be_bytes([ip[6], ip[7]]),
            u16::from_be_bytes([ip[8], ip[9]]),
            u16::from_be_bytes([ip[10], ip[11]]),
            u16::from_be_bytes([ip[12], ip[13]]),
            u16::from_be_bytes([ip[14], ip[15]]),
        ))),
        _ => None,
    }
}
