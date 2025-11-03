use std::env;

use rust_dns::{algorithm::query_domain, compression::compress_domain, error::DnsError};

fn main() -> Result<(), DnsError> {
    let args: Vec<String> = env::args().collect();
    println!("{}", args.len());
    if args.len() < 2 {
        panic!("Need to add a website to query");
    }
    if args.len() > 2 {
        panic!("Only supports one query at a time");
    }
    let domain = &args[1];
    let compressed_domain = compress_domain(domain);
    let ips = query_domain(&compressed_domain)?;
    println!();
    println!("The ips for {} is:", domain);
    for &ip in ips.iter() {
        println!("{:?}", ip);
    }
    Ok(())
}
