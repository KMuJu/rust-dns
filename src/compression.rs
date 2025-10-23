pub fn compress_domain(domain: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    for label in domain.split(".") {
        let len = label.len();
        if len > 63 {
            panic!("Label to long");
        }
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_compress_domain_google_dns() {
        let output = compress_domain("dns.google.com");
        let expected = [
            3, b'd', b'n', b's', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        assert_eq!(output.as_slice(), expected);
    }

    #[test]
    fn test_compress_domain_nrk_no() {
        let output = compress_domain("nrk.no");
        let expected = [3, b'n', b'r', b'k', 2, b'n', b'o', 0];
        assert_eq!(output.as_slice(), expected);
    }
}
