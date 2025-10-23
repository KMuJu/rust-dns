use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
};

use rust_dns::{
    compression::compress_domain,
    message::{Encodable, Message},
};

fn main() -> io::Result<()> {
    let domain = compress_domain("www.batimes.com.ar");

    let message = Message::new(1, &domain);
    let mut buf = Vec::new();
    message.encode(&mut buf);

    println!("First message: {:?}", message);

    let sock_addr = SocketAddr::from(([198, 41, 0, 4], 53));
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(sock_addr)?;
    socket.send(&buf)?;

    let mut recv = [0u8; 512];
    let len = socket.recv(&mut recv)?;

    let response = Message::from_bytes(&recv[..len]).unwrap();
    let e = response.check_error();
    match e {
        Ok(()) => (),
        Err(err) => {
            panic!("Error in response: {}\n", err);
        }
    };

    let ips = response.get_ips();
    if let Some(ips) = ips {
        for ip in ips {
            let ip = match ip.len() {
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
            };
            println!("Ip: {:?}", ip);
        }
    }

    Ok(())
}
