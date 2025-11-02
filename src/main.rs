use rust_dns::{algorithm::query_domain, compression::compress_domain, error::DnsError};

fn main() -> Result<(), DnsError> {
    let domain = "www.batimes.com.ar";
    // let domain = "nrk.no";
    // let domain = "google.com";
    let compressed_domain = compress_domain(domain);
    let ips = query_domain(&compressed_domain)?;
    println!();
    println!("The ips for {} is:", domain);
    for &ip in ips.iter() {
        println!("{:?}", ip);
    }
    Ok(())
}
