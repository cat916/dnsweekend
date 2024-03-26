use std::{
    env,
    io::Error,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
};

const CLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const TYPE_NS: u16 = 2;
const RECURSION_DESIRED: u16 = 1 << 8;

#[derive(Debug)]
struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DNSHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend(self.id.to_be_bytes());
        result.extend(self.flags.to_be_bytes());
        result.extend(self.num_questions.to_be_bytes());
        result.extend(self.num_answers.to_be_bytes());
        result.extend(self.num_authorities.to_be_bytes());
        result.extend(self.num_additionals.to_be_bytes());
        result
    }

    fn from_bytes(data: &[u8]) -> (DNSHeader, usize) {
        let offset = 0;
        (
            DNSHeader {
                id: u16::from_be_bytes([data[offset], data[offset + 1]]),
                flags: u16::from_be_bytes([data[offset + 2], data[offset + 3]]),
                num_questions: u16::from_be_bytes([data[offset + 4], data[offset + 5]]),
                num_answers: u16::from_be_bytes([data[offset + 6], data[offset + 7]]),
                num_authorities: u16::from_be_bytes([data[offset + 8], data[offset + 9]]),
                num_additionals: u16::from_be_bytes([data[offset + 10], data[offset + 11]]),
            },
            offset + 12,
        )
    }
}

#[derive(Debug)]
struct DNSQuestion {
    qname: String,
    qtype: u16,
    qclass: u16,
}

impl DNSQuestion {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend(encode_dns_name(&self.qname));
        result.extend(self.qtype.to_be_bytes());
        result.extend(self.qclass.to_be_bytes());
        result
    }
    fn from_bytes(data: &[u8], offset: usize) -> (DNSQuestion, usize) {
        let (qname, offset) = decode_dns_name(data, offset);
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        (
            DNSQuestion {
                qname,
                qtype,
                qclass,
            },
            offset + 4,
        )
    }
}

#[derive(Debug)]
enum DNSRecordData {
    A(Ipv4Addr),
    NS(String),
    TXT(String),
    Data(Vec<u8>),
}

#[derive(Debug)]
struct DNSRecord {
    name: String,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdlength: u16,
    rdata: DNSRecordData,
}

impl DNSRecord {
    fn from_bytes(data: &[u8], offset: usize) -> (DNSRecord, usize) {
        let (name, offset) = decode_dns_name(data, offset);
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]);
        match rtype {
            TYPE_A => {
                let rdata = Ipv4Addr::new(
                    data[offset + 10],
                    data[offset + 11],
                    data[offset + 12],
                    data[offset + 13],
                );
                (
                    DNSRecord {
                        name,
                        rtype,
                        rclass,
                        ttl,
                        rdlength,
                        rdata: DNSRecordData::A(rdata),
                    },
                    offset + 14,
                )
            }
            TYPE_NS => {
                let (rdata, offset) = decode_dns_name(data, offset + 10);
                (
                    DNSRecord {
                        name,
                        rtype,
                        rclass,
                        ttl,
                        rdlength,
                        rdata: DNSRecordData::NS(rdata),
                    },
                    offset,
                )
            }
            _ => {
                let rdata = data[offset + 10..offset + 10 + rdlength as usize].to_vec();
                (
                    DNSRecord {
                        name,
                        rtype,
                        rclass,
                        ttl,
                        rdlength,
                        rdata: DNSRecordData::Data(rdata),
                    },
                    offset + 10 + rdlength as usize,
                )
            }
        }
    }
}

#[derive(Debug)]
struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
}

impl DNSPacket {
    fn from_bytes(data: &[u8]) -> DNSPacket {
        let (header, offset) = DNSHeader::from_bytes(data);
        let mut questions = Vec::new();
        let mut offset = offset;
        for _ in 0..header.num_questions {
            let (question, new_offset) = DNSQuestion::from_bytes(data, offset);
            questions.push(question);
            offset = new_offset;
        }
        let mut answers = Vec::new();
        for _ in 0..header.num_answers {
            let (answer, new_offset) = DNSRecord::from_bytes(data, offset);
            answers.push(answer);
            offset = new_offset;
        }
        let mut authorities = Vec::new();
        for _ in 0..header.num_authorities {
            let (authority, new_offset) = DNSRecord::from_bytes(data, offset);
            authorities.push(authority);
            offset = new_offset;
        }
        let mut additionals = Vec::new();
        for _ in 0..header.num_additionals {
            let (additional, new_offset) = DNSRecord::from_bytes(data, offset);
            additionals.push(additional);
            offset = new_offset;
        }
        DNSPacket {
            header,
            questions,
            answers,
            authorities,
            additionals,
        }
    }

    fn get_nameserver(&self) -> Option<String> {
        for record in &self.authorities {
            if record.rtype == TYPE_NS {
                match &record.rdata {
                    DNSRecordData::NS(ns) => return Some(ns.to_string()),
                    _ => return None,
                }
            }
        }
        None
    }

    fn get_nameserver_ip(&self) -> Option<String> {
        for record in &self.additionals {
            if record.rtype == TYPE_A {
                match &record.rdata {
                    DNSRecordData::A(ip) => return Some(ip.to_string()),
                    _ => return None,
                }
            }
        }
        None
    }

    fn get_ip_address(&self) -> Option<String> {
        for record in &self.answers {
            if record.rtype == TYPE_A {
                match &record.rdata {
                    DNSRecordData::A(ip) => return Some(ip.to_string()),
                    _ => return None,
                }
            }
        }
        None
    }
}

fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let header = DNSHeader {
        id: 0x1234,
        flags: 0,
        num_questions: 1,
        num_answers: 0,
        num_authorities: 0,
        num_additionals: 0,
    };
    let question = DNSQuestion {
        qname: name.to_string(),
        qtype,
        qclass: CLASS_IN,
    };
    let mut result = Vec::new();
    result.extend(header.to_bytes());
    result.extend(question.to_bytes());
    result
}

fn send_query(ip_address: &str, domain_name: &str, qtype: u16) -> Result<DNSPacket, Error> {
    let dest_addr: SocketAddr = format!("{}:53", ip_address)
        .parse()
        .expect("couldn't parse address");

    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    let query = build_query(domain_name, qtype);
    match socket.send_to(&query, dest_addr) {
        Ok(_) => {
            let mut buf = [0; 1024];
            match socket.recv_from(&mut buf) {
                Ok((size, _src)) => {
                    let response = &buf[..size];
                    Ok(DNSPacket::from_bytes(response))
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

fn resolve(domain_name: &str, qtype: u16) -> Result<String, Error> {
    // root name_server https://www.iana.org/domains/root/servers
    let mut name_server = "198.41.0.4".to_string();
    loop {
        println!("Querying {} for {}", name_server, domain_name);
        let packet = send_query(&name_server, domain_name, qtype)?;
        match packet.get_ip_address() {
            Some(ip_address) => return Ok(ip_address),
            None => match packet.get_nameserver_ip() {
                Some(ip) => name_server = ip,
                None => match packet.get_nameserver() {
                    Some(ns) => name_server = resolve(&ns, TYPE_A)?,
                    None => return Err(Error::new(std::io::ErrorKind::Other, "couldn't resolve")),
                },
            },
        }
    }
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for part in name.split('.') {
        result.push(part.len() as u8);
        result.extend(part.as_bytes());
    }
    result.push(0); // push 0 byte to the end
    result
}

fn decode_dns_name(data: &[u8], offset: usize) -> (String, usize) {
    let mut result = String::new();
    let mut offset = offset;
    loop {
        let len = data[offset] as usize;
        if len == 0 {
            break;
        }
        if result.len() > 0 {
            result.push('.');
        }
        if len & 0xc0 == 0xc0 {
            offset += 1;
            break;
        }
        result.push_str(
            std::str::from_utf8(&data[offset + 1..offset + 1 + len])
                .expect("couldn't convert to string"),
        );
        offset += len + 1;
    }
    (result, offset + 1)
}

fn ipv4_to_string(data: &[u8]) -> String {
    data.iter()
        .map(|byte| byte.to_string())
        .collect::<Vec<String>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_dns_name() {
        assert_eq!(
            encode_dns_name("www.google.com"),
            vec![
                3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0
            ]
        );
    }

    #[test]
    fn test_dns_header_to_bytes() {
        let header = DNSHeader {
            id: 0x1234,
            flags: 0x5678,
            num_questions: 1,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };
        assert_eq!(
            header.to_bytes(),
            vec![0x12, 0x34, 0x56, 0x78, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_dns_question_to_bytes() {
        let question = DNSQuestion {
            qname: "www.google.com".to_string(),
            qtype: 1,
            qclass: 1,
        };
        assert_eq!(
            question.to_bytes(),
            vec![
                3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
                0x00, 0x01, 0x00, 0x01
            ]
        );
    }

    #[test]
    fn test_dns_query() {
        let header = DNSHeader {
            id: 0x1234,
            flags: RECURSION_DESIRED,
            num_questions: 1,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };
        let question = DNSQuestion {
            qname: "example.com".to_string(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        let mut result = Vec::new();
        result.extend(header.to_bytes());
        result.extend(question.to_bytes());
        assert_eq!(
            result,
            vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01
            ]
        );
    }

    #[test]
    fn test_decode_dns_name() {
        assert_eq!(
            decode_dns_name(
                &[
                    3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o',
                    b'm', 0
                ],
                0
            ),
            ("www.google.com".to_string(), 16)
        );
    }
}

fn main() -> Result<(), Error> {
    env::args()
        .skip(1)
        .for_each(|domain_name| match resolve(&domain_name, TYPE_A) {
            Ok(ip_address) => println!("{}: {}", domain_name, ip_address),
            Err(e) => eprintln!("couldn't resolve {}: {}", domain_name, e),
        });
    Ok(())
}
