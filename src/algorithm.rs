use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use log::{debug, error};
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

fn print_domain(domain: &[u8]) -> String {
    let mut s = String::with_capacity(domain.len() - 1);
    for &b in &domain[1..] {
        if b < 32 {
            s.push('.');
        } else {
            s.push(b as char);
        }
    }
    s
}

/// Sends message to the servers, quitting after the first received packet that has no error
///
/// # Errors
///
/// This function will return an error if every server responds with error
fn send_and_receive(
    message: &Message,
    socket: &UdpSocket,
    servers: &[ServerInfo],
) -> Result<Vec<u8>, DnsError> {
    let mut buf = Vec::new();
    let mut recv = [0u8; 512];
    message.encode(&mut buf);

    for server in servers.iter() {
        let ip = server.ip.unwrap_or(ROOT_SERVER_IP);
        debug!("Sending message to: {:?}", ip);
        if let Err(e) = socket.send_to(&buf, SocketAddr::new(ip, PORT)) {
            error!("Errored in send_to: {}", e);
            continue;
        }
        match socket.recv_from(&mut recv) {
            Ok((l, recv_addr)) => {
                let recv_ip = convert_mapped_addr(recv_addr.ip());
                if recv_ip != ip {
                    error!(
                        "Received ip({}) is not the same as the one sent to({})",
                        recv_ip, ip
                    );
                    continue;
                }
                if error_in_message(message.get_id(), &recv[..l]).is_ok() {
                    return Ok(recv[..l].to_vec());
                }
            }
            Err(e) => {
                error!("Could not receive from socket: {}", e);
            }
        }
    }

    Err(DnsError::NoAvailableServers)
}

/// Handles the delegation returning the new servers list
///
/// # Errors
///
/// This function will return an error if there is no additionals and (no names in authorities, or if query domain errors for each name)
///
/// # Structure
///
/// if there are additional rrs
///     => next server ips are stored in their rdata
///
/// else if there are no authority rrs
///     => Error (should always have either additional or authority rrs)
///
/// else
///     => Authority rrs store the domains of servers with better answer
///     => Query the domains stored in the authority rrs
fn handle_delegation(
    response: &Message,
    resp_bytes: &[u8],
    domain: &[u8],
) -> Result<Vec<ServerInfo>, DnsError> {
    if response.get_arcount() > 0 {
        let mut servers = response.get_additional_info(resp_bytes);
        sort_server_list(&mut servers, domain);
        return Ok(servers);
    }

    let names = response.get_authorities_info(resp_bytes);
    for name in names.iter() {
        debug!("- {}", name);
    }
    if names.is_empty() {
        return Err(DnsError::InvalidFormat);
    }
    for name in names {
        match query_domain(&name.to_vec()) {
            Ok(ips) => {
                return Ok(ips
                    .iter()
                    .map(|&ip| ServerInfo {
                        name: CompressedName(Vec::new()),
                        ip: Some(ip),
                    })
                    .collect());
            }
            Err(e) => {
                error!("Error quering: {}", e);
            }
        }
    }

    Err(DnsError::InvalidDelegation)
}

pub fn query_domain(domain: &[u8]) -> Result<Vec<IpAddr>, DnsError> {
    let message = Message::new(random::<u16>(), domain);
    debug!("Querying domain: {}", print_domain(domain));
    debug!("");

    let socket = UdpSocket::bind("[::]:0")?;
    socket.set_read_timeout(Some(Duration::new(5, 0)))?;

    let mut servers = vec![ServerInfo {
        name: CompressedName(vec![b".".to_vec()]), // Empty
        ip: Some(ROOT_SERVER_IP),
    }];

    for _ in 0..MAX_DEPTH {
        let resp_bytes = &send_and_receive(&message, &socket, &servers)?;
        let response = Message::from_bytes(resp_bytes)?;
        let response_type = response.get_type();

        match response_type {
            ResponseType::Error => {
                error!("Invalid format of response");
                return Err(DnsError::InvalidFormat);
            }
            ResponseType::Answer => {
                let ips = response.get_answer_ips();
                if !ips.is_empty() {
                    return Ok(ips);
                }
                let cnames = response.get_cnames(resp_bytes);
                for name in cnames {
                    match query_domain(&name.to_vec()) {
                        Ok(ips) => return Ok(ips),
                        Err(e) => error!("Error when querying cname: {}", e),
                    };
                }
                break;
            }
            ResponseType::Delegation => {
                servers = handle_delegation(&response, resp_bytes, domain)?;
                message.inc();
            }
        };
    }

    Err(DnsError::MaxDepth)
}
