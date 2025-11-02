use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use rand::random;

use crate::{
    compression::CompressedName,
    error::DnsError,
    message::{Encodable, Message, ResponseType, error_in_message},
    net::convert_mapped_addr,
    server_info::{ServerInfo, sort_server_list},
};

const MAX_DEPTH: usize = 8;
const PORT: u16 = 53;
const ROOT_SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4));

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
    let message = Message::new(random::<u16>(), domain);
    print!("\nQuerying for domain: ");
    print_domain(domain);
    println!();

    let socket = UdpSocket::bind("[::]:0")?;
    socket.set_read_timeout(Some(Duration::new(5, 0)))?;

    let mut servers = vec![ServerInfo {
        name: CompressedName(Vec::new()),
        ip: Some(ROOT_SERVER_IP),
    }];

    for i in 0..MAX_DEPTH {
        let mut buf = Vec::new();
        let mut recv = [0u8; 512];
        message.encode(&mut buf);
        let mut len = 0;

        let mut got_valid_response = false;
        for server in servers.iter() {
            let ip = server.ip.unwrap_or(ROOT_SERVER_IP);
            println!("[{}] Sending message to: {:?}", i, ip);
            if let Err(e) = socket.send_to(&buf, SocketAddr::new(ip, PORT)) {
                eprintln!("Errored in send_to: {}", e);
                continue;
            }
            match socket.recv_from(&mut recv) {
                Ok((l, recv_addr)) => {
                    let recv_ip = convert_mapped_addr(recv_addr.ip());
                    if recv_ip != ip {
                        eprintln!(
                            "Received ip({}) is not the same as the one sent to({})",
                            recv_ip, ip
                        );
                        continue;
                    }
                    len = l;
                    if error_in_message(message.get_id(), &recv[..len]).is_ok() {
                        got_valid_response = true;
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Could not receive from socket: {}", e);
                }
            }
        }
        if !got_valid_response {
            return Err(DnsError::NoAvailableServers);
        }

        let resp_bytes = &recv[..len];
        let response = Message::from_bytes(resp_bytes)?;
        let response_type = response.get_type();

        match response_type {
            ResponseType::Error => return Err(DnsError::InvalidFormat),
            ResponseType::Answer => {
                let ips = response.get_answer_ips();
                return Ok(ips);
            }
            ResponseType::Delegation => {
                if response.get_arcount() > 0 {
                    servers = response.get_additional_info(resp_bytes);
                    sort_server_list(&mut servers, domain);
                    message.inc();
                } else {
                    let names = response.get_authorities_info(&recv[..len]);
                    for name in names.iter() {
                        println!("- {}", name);
                    }
                    for name in names {
                        if let Ok(ips) = query_domain(&name.to_vec()) {
                            servers = ips
                                .iter()
                                .map(|&ip| ServerInfo {
                                    name: CompressedName(Vec::new()),
                                    ip: Some(ip),
                                })
                                .collect();
                            message.inc();
                            break;
                        }
                    }
                }
            }
        };
    }

    Err(DnsError::MaxDepth)
}
