use rust_dns::{
    algorithm::{query_domain, recursive_query},
    compression::compress_domain,
    error::DnsError,
    log::set_verbose,
    vprintln,
};
use std::env;

#[derive(Debug)]
struct Options<'a> {
    verbose: bool,
    recursive: bool,
    domain: &'a String,
}

fn print_usage(program: &String) {
    println!("{} [--verbose | -v] [--recursive | -r] domain", program);
}

fn parse_args(args: &[String]) -> Result<Options, DnsError> {
    let res = {
        let mut verbose = false;
        let mut recursive = false;
        let mut domain = None;
        for arg in args[1..].iter() {
            if arg == "-v" || arg == "--verbose" {
                if verbose {
                    return Err(DnsError::WrongArgs);
                }
                verbose = true;
            } else if arg == "-r" || arg == "--recursive" {
                if recursive {
                    return Err(DnsError::WrongArgs);
                }
                recursive = true;
            } else {
                if domain.is_some() {
                    return Err(DnsError::WrongArgs);
                }
                domain = Some(arg);
            }
        }

        let domain = domain.ok_or(DnsError::WrongArgs)?;
        let options = Options {
            verbose,
            recursive,
            domain,
        };
        Ok(options)
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
    if args.len() < 2 || args.len() > 4 {
        print_usage(&args[0]);
        return Err(DnsError::WrongArgs);
    }
    let options = parse_args(&args)?;

    set_verbose(options.verbose);
    let compressed_domain = compress_domain(options.domain);

    let ips = match options.recursive {
        false => query_domain(&compressed_domain)?,
        true => recursive_query(&compress_domain("www.nrk.no"))?,
    };

    vprintln!();
    println!("The ips for {} is:", options.domain);
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
            "--recursive".to_string(),
            "domain".to_string(),
        ];

        let output = parse_args(&args);
        match output {
            Ok(o) if o.domain == "domain" && o.verbose && o.recursive => {}
            o => panic!("Test failed, got {:?}, expected Ok(...)", o),
        }
    }

    #[test]
    fn test_parse_args_no_verbose() {
        let args: Vec<String> = vec!["prog".to_string(), "domain".to_string()];

        let output = parse_args(&args);
        match output {
            Ok(o) if o.domain == "domain" && !o.verbose => {}
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
