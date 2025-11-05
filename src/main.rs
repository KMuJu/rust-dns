use rust_dns::{
    algorithm::query_domain, compression::compress_domain, error::DnsError, log::set_verbose,
    vprintln,
};
use std::env;

fn print_usage(program: &String) {
    println!("{} [--verbose] domain", program);
}

fn parse_args(args: &[String]) -> Result<(bool, &String), DnsError> {
    let res = {
        let mut verbose = false;
        let mut domain = None;
        for arg in args[1..].iter() {
            if arg == "-v" || arg == "--verbose" {
                verbose = true;
            } else {
                if domain.is_some() {
                    return Err(DnsError::WrongArgs);
                }
                domain = Some(arg);
            }
        }

        let domain = domain.ok_or(DnsError::WrongArgs)?;
        Ok((verbose, domain))
    };
    match res {
        Err(_) => {
            print_usage(&args[0]);
            res
        }
        _ => res,
    }
}

fn main() -> Result<(), DnsError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        print_usage(&args[0]);
        return Err(DnsError::WrongArgs);
    }
    let (is_verbose, domain) = parse_args(&args)?;

    set_verbose(is_verbose);
    let compressed_domain = compress_domain(domain);
    let ips = query_domain(&compressed_domain)?;
    vprintln!();
    println!("The ips for {} is:", domain);
    for &ip in ips.iter() {
        println!("{:?}", ip);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_args() {
        let args: Vec<String> = vec![
            "prog".to_string(),
            "--verbose".to_string(),
            "domain".to_string(),
        ];

        let output = parse_args(&args);
        match output {
            Ok((l, d)) if d == "domain" && l => {}
            o => panic!(
                "Test failed, got {:?}, expected Ok((\"domain\", Some(log::LevelFilter::Debug)))",
                o
            ),
        }
    }

    #[test]
    fn test_parse_args_no_verbose() {
        let args: Vec<String> = vec!["prog".to_string(), "domain".to_string()];

        let output = parse_args(&args);
        match output {
            Ok((l, d)) if d == "domain" && !l => {}
            o => panic!("Test failed, got {:?}, expected Ok((\"domain\", None))", o),
        }
    }

    #[test]
    fn test_parse_args_two_domains() {
        let args: Vec<String> = vec![
            "prog".to_string(),
            "domain".to_string(),
            "domain".to_string(),
        ];

        let output = parse_args(&args);
        match output {
            Err(DnsError::WrongArgs) => {}
            o => panic!(
                "Test failed, got {:?}, expected Ok((\"domain\", log::LevelFilter::Info))",
                o
            ),
        }
    }
}
