use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CompressedName(pub Vec<Vec<u8>>);

impl CompressedName {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.iter().flat_map(|v| v.iter()).cloned().collect()
    }
}

pub fn compress_domain(domain: &str) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    for label in domain.split(".") {
        let len = label.len();
        if len > 63 {
            panic!("Label too long");
        }
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf
}

impl fmt::Display for CompressedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first_label = true;

        for part in self.0.iter() {
            let mut i = 0usize;
            while i < part.len() {
                let len = part[i];
                if len == 0 {
                    break;
                }

                if len & 0xC0 == 0xC0 {
                    break;
                }

                let label_len = len as usize;
                i += 1;

                if i + label_len > part.len() {
                    break;
                }

                if !first_label {
                    write!(f, ".")?;
                }

                for &b in &part[i..i + label_len] {
                    write!(f, "{}", b as char)?;
                }

                first_label = false;
                i += label_len;
            }
        }

        if first_label {
            write!(f, ".")?;
        }

        Ok(())
    }
}

pub fn is_pointer(p: u8) -> bool {
    p & 0b11000000 == 0b11000000
}

fn pointer_to_offset(a: u8, b: u8) -> usize {
    (u16::from_be_bytes([a, b]) & 0x3FF) as usize
}

pub fn decompress(data: &[u8], message: &[u8]) -> CompressedName {
    let mut current: Vec<Vec<u8>> = Vec::new();
    let len = data.len();
    if len < 2 || !is_pointer(data[len - 2]) {
        current.push(data.to_vec());
    } else {
        // contains pointer
        if len > 2 {
            current.push(data[..len - 2].to_vec());
        }
        let offset = pointer_to_offset(data[len - 2], data[len - 1]);
        let mut end = offset;
        while end < message.len() && message[end] != 0 {
            if is_pointer(message[end]) {
                end += 1;
                break;
            }
            let label_len = message[end] as usize;
            end += 1 + label_len;
        }
        let pointer_value = decompress(&message[offset..=end], message);
        current.extend_from_slice(&pointer_value.0);
    }

    CompressedName(current)
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

    #[test]
    fn test_decompress_domain() {
        let message = [
            1, b'f', 3, b'i', b's', b'i', 4, b'a', b'r', b'p', b'a', 0, 3, b'f', b'o', b'o',
            0b11000000, 0, 0,
        ];
        let pointer = &message[12..18];
        let output = decompress(pointer, &message);
        let expected = CompressedName(vec![message[12..12 + 4].to_vec(), message[..12].to_vec()]);

        assert_eq!(output, expected);
    }
}
