use std::{cmp::Reverse, net::IpAddr};

use crate::compression::CompressedName;

#[derive(Clone)]
pub struct ServerInfo {
    pub name: CompressedName,
    pub ip: Option<IpAddr>,
}

/// Assumes server list is not empty
pub fn get_best_server(servers: &[ServerInfo], target: &[u8]) -> usize {
    let mut max_score: u32 = 0;
    let mut index: usize = 0;
    for (i, server) in servers.iter().enumerate() {
        let score = score_server(server, target);
        if score > max_score {
            index = i;
            max_score = score;
        }
    }

    index
}

pub fn sort_server_list(servers: &mut [ServerInfo], target: &[u8]) {
    servers.sort_by_key(|s| Reverse(score_server(s, target)));
}

fn score_server(server: &ServerInfo, target: &[u8]) -> u32 {
    let v: &Vec<Vec<u8>> = &server.name.0;
    let mut score = 0;
    let target_len = target.len();

    for (i, &b) in v.iter().flat_map(|s| s.iter()).rev().enumerate() {
        if i > 0 && b < 32 && b != 0 {
            score += 1;
        }
        if i >= target_len {
            break;
        }
        if b != target[target_len - 1 - i] {
            break;
        }
    }
    score
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::compression::CompressedName;

    #[test]
    fn test_decompress_domain() {
        let message = [
            1, b'f', 3, b'i', b's', b'i', 4, b'a', b'r', b'p', b'a', 0, 3, b'f', b'o', b'o',
            0b11000000, 0, 0,
        ];
        let name = CompressedName(vec![message[12..12 + 4].to_vec(), message[..11].to_vec()]); // foo.fisi.arpa

        let server = ServerInfo { name, ip: None };
        let target = [1, b'f', 4, b'a', b'r', b'p', b'a']; // f.arpa
        let score = score_server(&server, &target);
        assert_eq!(score, 1);

        let target = [4, b'f', b'i', b's', b'i', 4, b'a', b'r', b'p', b'a']; // fisi.arpa
        let score = score_server(&server, &target);
        assert_eq!(score, 2);

        let target = [
            3, b'f', b'o', b'o', 4, b'f', b'i', b's', b'i', 4, b'a', b'r', b'p', b'a',
        ]; // fisi.arpa
        let score = score_server(&server, &target);
        assert_eq!(score, 2);
    }
}
