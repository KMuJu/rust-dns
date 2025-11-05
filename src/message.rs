use std::{cell::Cell, net::IpAddr};

use rand::random;

use crate::{
    compression::{CompressedName, decompress, is_pointer},
    error::{DnsError, ParseError, ResponseCodeError},
    net::bytes_to_ip,
    server_info::ServerInfo,
};

#[derive(Debug, PartialEq, Eq)]
pub struct Message<'a> {
    header: Header,
    questions: Vec<Question<'a>>,
    answers: Vec<ResourceRecord<'a>>,
    authorities: Vec<ResourceRecord<'a>>,
    additionals: Vec<ResourceRecord<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
struct Header {
    id: Cell<u16>,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

#[derive(Debug, PartialEq, Eq)]
struct Question<'a> {
    qname: &'a [u8],
    qtype: u16,
    qclass: u16,
}

#[derive(Debug, PartialEq, Eq)]
struct ResourceRecord<'a> {
    rname: &'a [u8],
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdlength: u16,
    rdata: &'a [u8],
}

#[derive(Debug)]
pub enum ResponseType {
    Answer,
    Delegation,
    Error,
}

impl<'a> Message<'a> {
    pub fn new(id: u16, domain: &'a [u8], recursion: bool) -> Self {
        Self {
            header: Header::new(id, false, false, false, recursion, 0),
            questions: vec![Question::<'a> {
                qname: domain,
                qtype: 1,
                qclass: 1,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn get_id(&self) -> u16 {
        self.header.id.get()
    }

    pub fn get_ancount(&self) -> u16 {
        self.header.ancount
    }

    pub fn get_nscount(&self) -> u16 {
        self.header.nscount
    }

    pub fn get_arcount(&self) -> u16 {
        self.header.arcount
    }

    pub fn check_error_response(&self, request: &Message) -> Result<(), DnsError> {
        self.header.check_error()?;
        (self.header.id == request.header.id)
            .then_some(())
            .ok_or(DnsError::InvalidResponseID)
    }

    pub fn new_id(&self) {
        self.header.id.set(random::<u16>());
    }

    pub fn inc(&self) {
        self.header.id.set(self.header.id.get() + 1)
    }

    pub fn get_type(&self) -> ResponseType {
        if self.header.ancount > 0 {
            return ResponseType::Answer;
        }
        if self.header.nscount > 0 {
            return ResponseType::Delegation;
        }
        ResponseType::Error
    }

    pub fn is_cname(&self) -> bool {
        self.answers.iter().any(|a| a.rtype == 5)
    }

    pub fn get_cnames(&self, bytes: &[u8]) -> Vec<CompressedName> {
        let mut cnames = Vec::new();
        for answer in self.answers.iter() {
            if answer.rtype != 5 {
                continue;
            }
            cnames.push(decompress(answer.rdata, bytes));
        }
        cnames
    }

    pub fn get_additional_info(&self, bytes: &[u8]) -> Vec<ServerInfo> {
        let mut servers = Vec::with_capacity(self.header.arcount as usize);
        for additional in &self.additionals {
            servers.push(ServerInfo {
                name: decompress(additional.rname, bytes),
                ip: bytes_to_ip(additional.rdata),
            });
        }

        servers
    }

    pub fn get_authorities_info(&self, bytes: &[u8]) -> Vec<CompressedName> {
        let mut names = Vec::with_capacity(self.header.nscount as usize);
        for additional in &self.authorities {
            names.push(decompress(additional.rdata, bytes));
        }

        names
    }

    pub fn get_answer_ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::with_capacity(self.header.ancount as usize);
        for answer in &self.answers {
            if answer.rtype != 1 {
                continue;
            }
            if let Some(ip) = bytes_to_ip(answer.rdata) {
                ips.push(ip);
            }
        }

        ips
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let header = Header::from_bytes(bytes)?;
        let mut questions = Vec::with_capacity(header.qdcount as usize);
        let mut answers = Vec::with_capacity(header.ancount as usize);
        let mut authorities = Vec::with_capacity(header.nscount as usize);
        let mut additionals = Vec::with_capacity(header.arcount as usize);

        let mut offset = 12;
        for _ in 0..header.qdcount {
            let (q, s) = Question::from_bytes(bytes, offset)?;
            questions.push(q);
            offset = s;
        }
        for _ in 0..header.ancount {
            let (r, s) = ResourceRecord::from_bytes(bytes, offset)?;
            answers.push(r);
            offset = s;
        }
        for _ in 0..header.nscount {
            let (r, s) = ResourceRecord::from_bytes(bytes, offset)?;
            authorities.push(r);
            offset = s;
        }
        for _ in 0..header.arcount {
            let (r, s) = ResourceRecord::from_bytes(bytes, offset)?;
            additionals.push(r);
            offset = s;
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

impl Header {
    fn new(id: u16, qr: bool, aa: bool, tc: bool, rd: bool, rcode: u8) -> Self {
        let mut flags: u16 = (rcode & 15).into();
        if qr {
            flags |= 1 << 15;
        }
        if aa {
            flags |= 1 << 10;
        }
        if tc {
            flags |= 1 << 9;
        }
        if rd {
            flags |= 1 << 8;
        }
        Self {
            id: id.into(),
            flags,
            qdcount: 1,
            ancount: 0,
            arcount: 0,
            nscount: 0,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 12 {
            return Err(ParseError::InvalidHeader);
        }
        Ok(Header {
            id: u16::from_be_bytes([bytes[0], bytes[1]]).into(),
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
            ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
            nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
            arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }

    fn check_error(&self) -> Result<(), ResponseCodeError> {
        match self.flags & 0xf {
            0 => Ok(()),
            1 => Err(ResponseCodeError::FormatError),
            2 => Err(ResponseCodeError::ServerFailure),
            3 => Err(ResponseCodeError::NameError),
            4 => Err(ResponseCodeError::NotImplemented),
            5 => Err(ResponseCodeError::Refused),
            _ => Ok(()),
        }
    }
}

impl<'a> Question<'a> {
    fn from_bytes(bytes: &'a [u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let mut end = offset;
        while end < bytes.len() && bytes[end] != 0 {
            if is_pointer(bytes[end]) {
                end += 1;
                break;
            }
            let label_len = bytes[end] as usize;
            end += 1 + label_len;
        }
        end += 1;
        if end + 4 > bytes.len() {
            return Err(ParseError::InvalidQuestion);
        }
        let qname = &bytes[offset..end];
        let qtype = u16::from_be_bytes([bytes[end], bytes[end + 1]]);
        let qclass = u16::from_be_bytes([bytes[end + 2], bytes[end + 3]]);
        end += 4;

        Ok((
            Self {
                qname,
                qtype,
                qclass,
            },
            end,
        ))
    }
}

impl<'a> ResourceRecord<'a> {
    fn from_bytes(bytes: &'a [u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let mut end = offset;
        while end < bytes.len() && bytes[end] != 0 {
            if is_pointer(bytes[end]) {
                end += 1;
                break;
            }
            let label_len = bytes[end] as usize;
            end += 1 + label_len;
        }
        end += 1;
        if end + 10 > bytes.len() {
            return Err(ParseError::InvalidResourcRecord);
        }
        let rname = &bytes[offset..end];
        let rtype = u16::from_be_bytes([bytes[end], bytes[end + 1]]);
        let rclass = u16::from_be_bytes([bytes[end + 2], bytes[end + 3]]);
        let ttl = u32::from_be_bytes([
            bytes[end + 4],
            bytes[end + 5],
            bytes[end + 6],
            bytes[end + 7],
        ]);
        let rdlength = u16::from_be_bytes([bytes[end + 8], bytes[end + 9]]);
        end += 10;
        if end + (rdlength as usize) > bytes.len() {
            return Err(ParseError::InvalidResourcRecord);
        }
        let rdata = &bytes[end..end + rdlength as usize];
        end += rdlength as usize;
        Ok((
            Self {
                rname,
                rtype,
                rclass,
                ttl,
                rdlength,
                rdata,
            },
            end,
        ))
    }
}

pub trait Encodable {
    fn encode(&self, buf: &mut Vec<u8>);
}

impl Encodable for Message<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.header.encode(buf);

        for question in &self.questions {
            question.encode(buf);
        }

        for rr in &self.answers {
            rr.encode(buf);
        }

        for rr in &self.authorities {
            rr.encode(buf);
        }

        for rr in &self.additionals {
            rr.encode(buf);
        }
    }
}

impl Encodable for Header {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.id.get().to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&self.qdcount.to_be_bytes());
        buf.extend_from_slice(&self.ancount.to_be_bytes());
        buf.extend_from_slice(&self.nscount.to_be_bytes());
        buf.extend_from_slice(&self.arcount.to_be_bytes());
    }
}

impl Encodable for Question<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.qname);
        buf.extend_from_slice(&self.qtype.to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());
    }
}

impl Encodable for ResourceRecord<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.rname);
        buf.extend_from_slice(&self.rtype.to_be_bytes());
        buf.extend_from_slice(&self.rclass.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&self.rdlength.to_be_bytes());
        buf.extend_from_slice(self.rdata);
    }
}

pub fn error_in_message(id: u16, bytes: &[u8]) -> Result<(), DnsError> {
    if bytes.len() < 12 {
        return Err(DnsError::ParsingError(ParseError::InvalidHeader));
    }
    let resp_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
    let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);

    if id != resp_id {
        return Err(DnsError::InvalidResponseID);
    }
    match flags & 0xf {
        0 => Ok(()),
        1 => Err(ResponseCodeError::FormatError),
        2 => Err(ResponseCodeError::ServerFailure),
        3 => Err(ResponseCodeError::NameError),
        4 => Err(ResponseCodeError::NotImplemented),
        5 => Err(ResponseCodeError::Refused),
        _ => Ok(()),
    }?;

    if ancount == 0 && nscount == 0 {
        return Err(DnsError::InvalidFormat);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_header_encode_from_bytes_eq() {
        let header = Header::new(1, false, false, false, false, 0);
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let output = Header::from_bytes(&buf);

        assert_eq!(output.unwrap(), header);
    }

    #[test]
    fn test_question_encode_from_bytes_eq() {
        let domains: [u8; 12] = [
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let question = Question {
            qname: &domains,
            qtype: 1,
            qclass: 1,
        };
        let mut buf = Vec::new();
        question.encode(&mut buf);
        let output = Question::from_bytes(&buf, 0);
        match output {
            Ok((q, s)) => {
                assert_eq!(q, question);
                assert_eq!(s, 12 + 4);
            }
            _ => panic!("Question::from_bytes failed"),
        }
    }

    #[test]
    fn test_question_from_bytes_fail() {
        let buf: [u8; 12] = [
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let output = Question::from_bytes(&buf, 0);
        match output {
            Err(ParseError::InvalidQuestion) => {}
            _ => panic!("Bytes are not long enough"),
        }
    }

    #[test]
    fn test_rr_encode_from_bytes_eq() {
        let domains: [u8; 12] = [
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let rdata = [b'1', b'2', b'3'];
        let rr = ResourceRecord {
            rname: &domains,
            rtype: 1,
            rclass: 1,
            ttl: 1,
            rdlength: rdata.len() as u16,
            rdata: &rdata,
        };
        let mut buf = Vec::new();
        rr.encode(&mut buf);
        let output = ResourceRecord::from_bytes(&buf, 0);
        match output {
            Ok((r, s)) => {
                assert_eq!(r, rr);
                assert_eq!(s, 12 + 10 + rdata.len());
            }
            _ => panic!("ResourceRecord::from_bytes failed"),
        }
    }

    #[test]
    fn test_message_encode_from_bytes_eq() {
        let domains: [u8; 12] = [
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let message = Message::new(1, &domains);
        let mut buf = Vec::new();
        message.encode(&mut buf);
        let output = Message::from_bytes(&buf);
        match output {
            Ok(m) => {
                assert_eq!(m, message);
            }
            _ => panic!("Message::from_bytes failed"),
        }
    }

    #[test]
    fn test_rr_from_bytes_out_of_bounds() {
        // minimal invalid record: too short for rdata
        let bad = [
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, 0, 1, 0, 1, // type/class
            0, 0, 0, 0, // ttl
            0, 4, // rdlength claims 4
            1, 2, // but only 2 bytes of rdata!
        ];
        let result = ResourceRecord::from_bytes(&bad, 0);
        assert!(matches!(result, Err(ParseError::InvalidResourcRecord)));
    }

    #[test]
    fn test_header_flags_rcode_handling() {
        let mut bytes = [0u8; 12];
        bytes[3] = 3; // set rcode = 3 (NameError)
        let header = Header::from_bytes(&bytes).unwrap();
        let res = header.check_error();
        assert!(matches!(res, Err(ResponseCodeError::NameError)));
    }
}
