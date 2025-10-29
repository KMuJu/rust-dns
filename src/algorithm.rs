use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    time::Duration,
};

use crate::{
    error::DnsError,
    message::{Encodable, Message, ResponseType},
    server_info::get_best_server,
};

const MAX_DEPTH: usize = 8;
const PORT: u16 = 53;
const ROOT_SERVER: ([u8; 4], u16) = ([198, 41, 0, 4], PORT);

fn print_domain(domain: &[u8]) {
    for &b in &domain[1..] {
        if b < 32 {
            print!(".");
        } else {
            print!("{}", b as char);
        }
    }
}

pub fn query_domain(domain: &[u8]) -> Result<Vec<IpAddr>, DnsError> {
    let message = Message::new(1, domain);
    print!("\nQuerying for domain: ");
    print_domain(domain);
    println!();

    // println!("First message: {:?}\n", message);

    let mut sock_addr = SocketAddr::from(ROOT_SERVER);
    let socket = UdpSocket::bind("[::]:0")?;
    socket.set_read_timeout(Some(Duration::new(5, 0)))?;

    // socket.connect(sock_addr)?;
    for i in 0..MAX_DEPTH {
        println!("[{}] Sending message to: {:?}", i, sock_addr);
        // println!("Sending message: {:?}\n", message);

        let mut buf = Vec::new();
        let mut recv = [0u8; 512];
        message.encode(&mut buf);

        socket.send_to(&buf, sock_addr)?;
        let len = socket.recv(&mut recv)?;
        let response = Message::from_bytes(&recv[..len])?;
        response.check_error_response(&message)?;

        let response_type = response.get_type();

        match response_type {
            ResponseType::Error => return Err(DnsError::InvalidFormat),
            ResponseType::Answer => {
                let ips = response.get_answer_ips();
                return Ok(ips);
            }
            ResponseType::Delegation => {
                if response.get_arcount() > 0 {
                    let servers = response.get_additional_info(&recv[..len]);
                    let best_index = get_best_server(&servers, domain);
                    let ip = servers[best_index].ip.ok_or(DnsError::InvalidFormat)?;
                    println!("Best server: {} - {:?}", servers[best_index].name, ip);
                    sock_addr = SocketAddr::new(ip, PORT);
                    message.inc();
                } else {
                    let names = response.get_authorities_info(&recv[..len]);
                    for name in names.iter() {
                        println!("- {}", name);
                    }
                    for name in names {
                        if let Ok(ips) = query_domain(&name.to_vec()) {
                            sock_addr = SocketAddr::new(ips[0], PORT);
                            message.inc();
                        }
                    }
                    // for &ip in ips.iter() {
                    //     println!("{:?}", ip);
                    // }
                    // break;
                }
            }
        };
    }

    Err(DnsError::MaxDepth)
}
