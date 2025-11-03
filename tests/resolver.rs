use rust_dns::{algorithm::query_domain, compression::compress_domain};
use std::net::ToSocketAddrs;

fn resolve_with_system(domain: &str) -> Vec<String> {
    // Uses OS resolver (often glibc / systemd-resolved / etc.)
    match (domain, 53).to_socket_addrs() {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(_) => vec![],
    }
}

#[test]
fn test_dns_matches_system_resolver() {
    let domain = "example.com";
    let system_ips = resolve_with_system(domain);
    for ip in system_ips.iter() {
        println!("{}", ip);
    }

    let result = query_domain(&compress_domain(domain)).expect("our resolver should succeed");
    let our_ips = result.iter().map(|r| r.to_string()).collect::<Vec<_>>();

    // At least one IP should match what the system resolver found
    assert!(
        our_ips.iter().any(|ip| system_ips.contains(ip)),
        "our resolver returned {:?}, system resolver returned {:?}",
        our_ips,
        system_ips
    );
}

#[test]
fn test_dns_with_cname_matches_system_resolver() {
    let domain = "www.nrk.no";
    let system_ips = resolve_with_system(domain);
    for ip in system_ips.iter() {
        println!("{}", ip);
    }

    let result = query_domain(&compress_domain(domain)).expect("our resolver should succeed");
    let our_ips = result.iter().map(|r| r.to_string()).collect::<Vec<_>>();

    // At least one IP should match what the system resolver found
    assert!(
        our_ips.iter().any(|ip| system_ips.contains(ip)),
        "our resolver returned {:?}, system resolver returned {:?}",
        our_ips,
        system_ips
    );
}
