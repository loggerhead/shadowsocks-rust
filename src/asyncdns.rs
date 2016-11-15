use std::fmt;
use std::env;
use std::convert::From;
use std::str::FromStr;
use std::io::Cursor;
use std::net::{ToSocketAddrs, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use rand;
use regex::Regex;
use lru_time_cache::LruCache;
use mio::udp::UdpSocket;
use mio::{Token, EventSet, EventLoop, PollOpt};

use error::{Result, SocketError};
use relay::Relay;
use collections::{Set, Dict};
use network::{NetworkWriteBytes, NetworkReadBytes};
use network::{is_ipv4, is_ipv6, is_ip, slice2ip4, slice2ip6, pair2addr};
use util::{RcCell, handle_every_line, slice2string, slice2str};

// All communications inside of the domain protocol are carried in a single
// format called a message.  The top level format of message is divided
// into 5 sections (some of which are empty in certain cases) shown below:
//
//     +---------------------+
//     |        Header       |
//     +---------------------+
//     |       Question      | the question for the name server
//     +---------------------+
//     |        Answer       | RRs answering the question
//     +---------------------+
//     |      Authority      | RRs pointing toward an authority
//     +---------------------+
//     |      Additional     | RRs holding additional information
//     +---------------------+
//
// The header section is always present.  The header includes fields that
// specify which of the remaining sections are present, and also specify
// whether the message is a query or a response, a standard query or some
// other opcode, etc.

// The header section format:
//
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct HostIpPair(pub String, pub String);
struct ResponseRecord(String, String, u16, u16);
struct ResponseHeader(u16, u16, u16, u16, u16, u16, u16, u16, u16);

const BUF_SIZE: usize = 1024;

pub enum Error {
    Timeout,
    BufferEmpty,
    EmptyHostName,
    InvalidResponse,
    BuildRequestFailed,
    NoPreferredResponse,
    InvalidHost(String),
    UnknownHost(String),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Timeout => write!(f, "timeout"),
            Error::BufferEmpty => write!(f, "no buffered data available"),
            Error::EmptyHostName => write!(f, "empty hostname"),
            Error::InvalidResponse => write!(f, "invalid response"),
            Error::BuildRequestFailed => write!(f, "build dns request failed"),
            Error::NoPreferredResponse => write!(f, "no preferred response"),
            Error::InvalidHost(ref host) => write!(f, "invalid host {}", host),
            Error::UnknownHost(ref host) => write!(f, "unknown host {}", host),
        }
    }
}

pub trait Caller {
    fn get_id(&self) -> Token;
    fn handle_dns_resolved(&mut self,
                           event_loop: &mut EventLoop<Relay>,
                           res: Result<Option<HostIpPair>>);
}

struct DnsResponse {
    hostname: String,
    questions: Vec<(String, u16, u16)>,
    answers: Vec<(String, u16, u16)>,
}

impl fmt::Debug for DnsResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {:?}", self.hostname, self.answers)
    }
}

impl DnsResponse {
    fn new() -> DnsResponse {
        DnsResponse {
            hostname: String::new(),
            questions: Vec::new(),
            answers: Vec::new(),
        }
    }
}


#[derive(Debug, Clone, Copy)]
enum HostnameStatus {
    First,
    Second,
}

pub struct DnsResolver {
    prefer_ipv6: bool,
    token: Token,
    hosts: Dict<String, String>,
    cache: LruCache<String, String>,
    callers: Dict<Token, RcCell<Caller>>,
    hostname_status: Dict<String, HostnameStatus>,
    token_to_hostname: Dict<Token, String>,
    hostname_to_tokens: Dict<String, Set<Token>>,
    sock: UdpSocket,
    servers: Vec<String>,
    qtypes: Vec<u16>,
    receive_buf: Option<Vec<u8>>,
}

impl DnsResolver {
    pub fn new(token: Token,
               server_list: Option<Vec<String>>,
               prefer_ipv6: bool)
               -> Result<DnsResolver> {
        // pre-define DNS server list
        let servers = match server_list {
            Some(servers) => servers,
            None => parse_resolv(prefer_ipv6),
        };
        let (qtypes, addr) = if prefer_ipv6 {
            (vec![QType::AAAA, QType::A], "[::]:0")
        } else {
            (vec![QType::A, QType::AAAA], "0.0.0.0:0")
        };
        let addr = SocketAddr::from_str(addr).map_err(|_| SocketError::InitSocketFailed)?;
        let sock = UdpSocket::bound(&addr).map_err(|_| SocketError::InitSocketFailed)?;
        let hosts = parse_hosts(prefer_ipv6);
        let cache_timeout = Duration::new(600, 0);

        Ok(DnsResolver {
            prefer_ipv6: prefer_ipv6,
            token: token,
            servers: servers,
            hosts: hosts,
            cache: LruCache::with_expiry_duration(cache_timeout),
            callers: Dict::default(),
            hostname_status: Dict::default(),
            token_to_hostname: Dict::default(),
            hostname_to_tokens: Dict::default(),
            sock: sock,
            qtypes: qtypes,
            receive_buf: Some(Vec::with_capacity(BUF_SIZE)),
        })
    }

    pub fn add_caller(&mut self, caller: RcCell<Caller>) {
        let token = caller.borrow().get_id();
        self.callers.insert(token, caller);
    }

    pub fn remove_caller(&mut self, token: Token) -> bool {
        if let Some(hostname) = self.token_to_hostname.remove(&token) {
            self.hostname_to_tokens.get_mut(&hostname).map(|tokens| tokens.remove(&token));
            if self.hostname_to_tokens.get(&hostname).unwrap().is_empty() {
                self.hostname_to_tokens.remove(&hostname);
                self.hostname_status.remove(&hostname);
            }
        }

        self.callers.remove(&token).is_some()
    }

    fn send_request(&self, hostname: String, qtype: u16) -> Result<()> {
        debug!("send dns query of {}", &hostname);
        for server in &self.servers {
            let addr = pair2addr(server, 53)?;
            let req = build_request(&hostname, qtype).ok_or(Error::BuildRequestFailed)?;
            self.sock.send_to(&req, &addr)?;
        }
        Ok(())
    }

    fn receive_data_into_buf(&mut self) -> Result<()> {
        let mut res = Ok(());
        let mut buf = self.receive_buf.take().unwrap();

        new_fat_slice_from_vec!(buf_slice, buf);
        match self.sock.recv_from(buf_slice) {
            Ok(None) => {}
            Ok(Some((nread, _addr))) => unsafe {
                buf.set_len(nread);
            },
            Err(e) => res = err_from!(e),
        }
        self.receive_buf = Some(buf);
        res
    }

    fn local_resolve(&mut self, hostname: &String) -> Result<Option<HostIpPair>> {
        if hostname.is_empty() {
            err_from!(Error::EmptyHostName)
        } else if is_ip(hostname) {
            Ok(Some(HostIpPair(hostname.to_string(), hostname.to_string())))
        } else if self.hosts.contains_key(hostname) {
            let ip = self.hosts[hostname].clone();
            Ok(Some(HostIpPair(hostname.to_string(), ip)))
        } else if self.cache.contains_key(hostname) {
            let ip = self.cache.get_mut(hostname).unwrap();
            Ok(Some(HostIpPair(hostname.to_string(), ip.clone())))
        } else if !is_valid_hostname(hostname) {
            err_from!(Error::InvalidHost(hostname.clone()))
        } else {
            Ok(None)
        }
    }

    pub fn block_resolve(&mut self, hostname: String) -> Result<Option<HostIpPair>> {
        match self.local_resolve(&hostname) {
            Ok(None) => {
                let mut addr_v4 = None;
                let mut addr_v6 = None;

                for addr in (hostname.as_str(), 0).to_socket_addrs()? {
                    match addr {
                        SocketAddr::V4(addr) => {
                            if addr_v4.is_none() {
                                addr_v4 = Some(addr);
                            }
                        }
                        SocketAddr::V6(addr) => {
                            if addr_v6.is_none() {
                                addr_v6 = Some(addr);
                            }
                        }
                    }

                    if self.prefer_ipv6 && addr_v6.is_some() {
                        return Ok(Some(HostIpPair(hostname.to_string(),
                                                  addr_v6.unwrap().ip().to_string())));
                    }
                    if !self.prefer_ipv6 && addr_v4.is_some() {
                        return Ok(Some(HostIpPair(hostname.to_string(),
                                                  addr_v4.unwrap().ip().to_string())));
                    }
                }

                Ok(None)
            }
            res => res,
        }
    }

    // TODO: change to `&str` (wait `lru_time_cache` release the new version)
    pub fn resolve(&mut self, token: Token, hostname: String) -> Result<Option<HostIpPair>> {
        match self.local_resolve(&hostname) {
            Ok(None) => {
                // if this is the first time that any caller query the hostname
                if !self.hostname_to_tokens.contains_key(&hostname) {
                    self.hostname_status.insert(hostname.clone(), HostnameStatus::First);
                    self.hostname_to_tokens.insert(hostname.clone(), Set::default());
                }
                self.hostname_to_tokens.get_mut(&hostname).unwrap().insert(token);
                self.token_to_hostname.insert(token, hostname.clone());

                self.send_request(hostname, self.qtypes[0])?;
                Ok(None)
            }
            res => res,
        }
    }

    fn call_callback(&mut self, event_loop: &mut EventLoop<Relay>, hostname: String, ip: String) {
        self.hostname_status.remove(&hostname);
        if let Some(tokens) = self.hostname_to_tokens.remove(&hostname) {
            for token in &tokens {
                self.token_to_hostname.remove(token);

                let caller = self.callers.get_mut(token).unwrap();
                if ip.is_empty() {
                    caller.borrow_mut()
                        .handle_dns_resolved(event_loop,
                                             err_from!(Error::UnknownHost(hostname.clone())));
                } else {
                    let hostname_ip = HostIpPair(hostname.clone(), ip.clone());
                    caller.borrow_mut().handle_dns_resolved(event_loop, Ok(Some(hostname_ip)));
                }
            }
        }
    }

    fn handle_recevied(&mut self) -> Result<Option<HostIpPair>> {
        let mut res = err_from!(Error::BufferEmpty);
        let receive_buf = self.receive_buf.take().unwrap();
        if receive_buf.is_empty() {
            return res;
        }

        if let Some(response) = parse_response(&receive_buf) {
            let mut ip = String::new();
            for answer in &response.answers {
                if (answer.1 == QType::A || answer.1 == QType::AAAA) && answer.2 == QClass::IN {
                    ip = answer.0.clone();
                    break;
                }
            }

            let hostname = response.hostname;
            let hostname_status = match self.hostname_status.get(&hostname) {
                Some(&HostnameStatus::First) => 1,
                Some(&HostnameStatus::Second) => 2,
                _ => 0,
            };

            if ip.is_empty() && hostname_status == 1 {
                self.hostname_status.insert(hostname.clone(), HostnameStatus::Second);
                self.send_request(hostname, self.qtypes[1])?;
                res = Ok(None);
            } else if !ip.is_empty() {
                self.cache.insert(hostname.clone(), ip.clone());
                res = Ok(Some(HostIpPair(hostname, ip)));
            } else if hostname_status == 2 {
                res = err_from!(Error::NoPreferredResponse);

                for question in response.questions {
                    if question.1 == self.qtypes[1] {
                        ip.clear();
                        res = Ok(Some(HostIpPair(hostname, ip)));
                        break;
                    }
                }
            }
        } else {
            res = err_from!(Error::InvalidResponse);
        }

        self.receive_buf = Some(receive_buf);
        res
    }

    fn do_register(&mut self,
                   event_loop: &mut EventLoop<Relay>,
                   is_reregister: bool)
                   -> Result<()> {
        let events = EventSet::readable();
        let pollopts = PollOpt::edge() | PollOpt::oneshot();

        if is_reregister {
            event_loop.reregister(&self.sock, self.token, events, pollopts)
                .map_err(From::from)
        } else {
            event_loop.register(&self.sock, self.token, events, pollopts).map_err(From::from)
        }
    }

    pub fn register(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        self.do_register(event_loop, false)
    }

    fn reregister(&mut self, event_loop: &mut EventLoop<Relay>) -> Result<()> {
        self.do_register(event_loop, true)
    }

    pub fn handle_events(&mut self,
                         event_loop: &mut EventLoop<Relay>,
                         events: EventSet)
                         -> Result<()> {
        if events.is_error() {
            error!("events error on DNS socket");
            let _ = event_loop.deregister(&self.sock);
            self.register(event_loop)?;

            for caller in self.callers.values() {
                caller.borrow_mut()
                    .handle_dns_resolved(event_loop, err_from!(SocketError::EventError));
            }

            self.callers.clear();
            self.hostname_status.clear();
            self.token_to_hostname.clear();
            self.hostname_to_tokens.clear();
            err_from!(SocketError::EventError)
        } else {
            self.receive_data_into_buf()?;
            if let Ok(Some(HostIpPair(hostname, ip))) = self.handle_recevied() {
                self.call_callback(event_loop, hostname, ip);
            }
            self.reregister(event_loop)
        }
    }
}

// For detail, see page 7 of RFC 1035
fn build_address(address: &str) -> Option<Vec<u8>> {
    let mut v = vec![];
    let bytes = address.as_bytes();
    for label in bytes.split(|ch| *ch == b'.') {
        match label.len() {
            0 => continue,
            n if n > 63 => return None,
            n => {
                v.push(n as u8);
                v.extend_from_slice(label);
            }
        }
    }

    v.push(0);
    Some(v)
}

// For detail, see page 24 of RFC 1035
fn build_request(address: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut r = vec![];
    // The header section:
    //
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |               random request_id               |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     | 0|     0     | 0| 0| 1| 0|   0    |     0     |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                       1                       |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                       0                       |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                       0                       |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                       0                       |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    let request_id = rand::random::<u16>();

    pack!(u16, r, request_id);
    pack!(u8, r, 1);
    pack!(u8, r, 0);
    pack!(u16, r, 1);
    pack!(u16, r, 0);
    pack!(u16, r, 0);
    pack!(u16, r, 0);
    // address
    let addr = try_opt!(build_address(address));
    r.extend(addr);
    // qtype and qclass
    pack!(u16, r, qtype);
    pack!(u16, r, QClass::IN);

    Some(r)
}

// RDATA: a variable length string of octets that describes the resource.
//        The format of this information varies according to the TYPE and CLASS
//        of the resource record. For example, the if the TYPE is A
//        and the CLASS is IN, the RDATA field is a 4 octet ARPA Internet address.
fn parse_ip(addrtype: u16, data: &[u8], length: usize, offset: usize) -> Option<String> {
    let ip_part = &data[offset..offset + length];

    match addrtype {
        QType::A => slice2ip4(ip_part),
        QType::AAAA => slice2ip6(ip_part),
        QType::CNAME | QType::NS => Some(try_opt!(parse_name(data, offset as u16)).1),
        _ => slice2string(ip_part),
    }
}

// For detail, see page 29 of RFC 1035
fn parse_name(data: &[u8], offset: u16) -> Option<(u16, String)> {
    let mut p = offset as usize;
    let mut l = data[p];
    let mut labels: Vec<String> = Vec::new();

    while l > 0 {
        // if compressed
        if (l & 0b11000000) == 0b11000000 {
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //    | 1  1|                OFFSET                   |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            let mut tmp = Cursor::new(&data[p..p + 2]);
            let mut ptr = unpack!(u16, tmp);
            ptr &= 0x3FFF;
            let r = try_opt!(parse_name(data, ptr));
            labels.push(r.1);
            p += 2;
            return Some((p as u16 - offset, labels.join(".")));
        } else {
            labels.push(try_opt!(slice2string(&data[(p + 1)..(p + 1 + l as usize)])));
            p += 1 + l as usize;
        }

        l = data[p];
    }

    Some((p as u16 + 1 - offset, labels.join(".")))
}

// For detail, see page 27, 28 of RFC 1035
fn parse_record(data: &[u8], offset: u16, question: bool) -> Option<(u16, ResponseRecord)> {
    let (nlen, name) = try_opt!(parse_name(data, offset));

    // The question section format:
    //
    //                                     1  1  1  1  1  1
    //       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                                               |
    //     /                     QNAME                     /
    //     /                                               /
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                     QTYPE                     |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //     |                     QCLASS                    |
    //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    if question {
        let bytes = &data[(offset + nlen) as usize..(offset + nlen + 4) as usize];
        let mut record = Cursor::new(bytes);

        let record_type = unpack!(u16, record);
        let record_class = unpack!(u16, record);

        Some((nlen + 4, ResponseRecord(name, String::new(), record_type, record_class)))
        //                                    1  1  1  1  1  1
        //      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                                               |
        //    /                                               /
        //    /                      NAME                     /
        //    |                                               |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                      TYPE                     |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                     CLASS                     |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                      TTL                      |
        //    |                                               |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //    |                   RDLENGTH                    |
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        //    /                     RDATA                     /
        //    /                                               /
        //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    } else {
        let bytes = &data[(offset + nlen) as usize..(offset + nlen + 10) as usize];
        let mut record = Cursor::new(bytes);

        let record_type = unpack!(u16, record);
        let record_class = unpack!(u16, record);
        let _record_ttl = unpack!(u32, record);
        let record_rdlength = unpack!(u16, record);

        // RDATA
        let ip = try_opt!(parse_ip(record_type,
                                   data,
                                   record_rdlength as usize,
                                   (offset + nlen + 10) as usize));

        Some((nlen + 10 + record_rdlength, ResponseRecord(name, ip, record_type, record_class)))
    }
}

fn parse_header(data: &[u8]) -> Option<ResponseHeader> {
    if data.len() < 12 {
        return None;
    }

    let mut header = Cursor::new(data);

    let id = unpack!(u16, header);
    let byte3 = unpack!(u8, header);
    let byte4 = unpack!(u8, header);
    let qdcount = unpack!(u16, header);
    let ancount = unpack!(u16, header);
    let nscount = unpack!(u16, header);
    let arcount = unpack!(u16, header);
    let qr = (byte3 & 0b10000000) as u16;
    let tc = (byte3 & 0b00000010) as u16;
    let ra = (byte4 & 0b00000010) as u16;
    let rcode = (byte4 & 0b00001111) as u16;

    Some(ResponseHeader(id, qr, tc, ra, rcode, qdcount, ancount, nscount, arcount))
}

fn parse_records(data: &[u8],
                 offset: u16,
                 count: u16,
                 question: bool)
                 -> Option<(u16, Vec<ResponseRecord>)> {
    let mut records: Vec<ResponseRecord> = Vec::new();
    let mut offset = offset;

    for _i in 0..count {
        let (len, record) = try_opt!(parse_record(data, offset, question));
        offset += len;
        records.push(record);
    }

    Some((offset, records))
}

fn parse_response(data: &[u8]) -> Option<DnsResponse> {
    if data.len() < 12 {
        return None;
    }

    parse_header(data).and_then(|header| {
        let ResponseHeader(_id, _qr, _tc, _ra, _rcode, qdcount, ancount, _nscount, _arcount) =
            header;

        let offset = 12u16;
        let (offset, qds) = try_opt!(parse_records(data, offset, qdcount, true));
        let (_offset, ans) = try_opt!(parse_records(data, offset, ancount, false));
        // We don't need to parse the authority records and the additional records
        let (_offset, _nss) = try_opt!(parse_records(data, _offset, _nscount, false));
        let (_offset, _ars) = try_opt!(parse_records(data, _offset, _arcount, false));

        let mut response = DnsResponse::new();
        if !qds.is_empty() {
            response.hostname = qds[0].0.clone();
        }
        for an in qds {
            response.questions.push((an.1, an.2, an.3))
        }
        for an in ans {
            response.answers.push((an.1, an.2, an.3))
        }

        Some(response)
    })
}

fn parse_resolv(prefer_ipv6: bool) -> Vec<String> {
    let mut servers = vec![];

    let _ = handle_every_line("/etc/resolv.conf",
                              &mut |line| {
        if line.starts_with("nameserver") {
            if let Some(ip) = line.split_whitespace().nth(1) {
                if (prefer_ipv6 && is_ipv6(ip)) || (!prefer_ipv6 && is_ipv4(ip)) {
                    servers.push(ip.to_string());
                }
            }
        }
    });

    if servers.is_empty() {
        let dns_servers = if cfg!(feature = "sslocal") {
            vec!["114.114.114.114", "114.114.115.115"]
        } else {
            if prefer_ipv6 {
                vec!["2001:4860:4860::8888", "2001:4860:4860::8844"]
            } else {
                vec!["8.8.8.8", "8.8.4.4"]
            }
        };

        servers = dns_servers.into_iter().map(|s| s.to_string()).collect();
    }

    servers
}


fn parse_hosts(prefer_ipv6: bool) -> Dict<String, String> {
    let mut hosts = Dict::default();
    if prefer_ipv6 {
        hosts.insert("localhost".to_string(), "::1".to_string());
    } else {
        hosts.insert("localhost".to_string(), "127.0.0.1".to_string());
    }

    let hosts_path = if cfg!(target_family = "UNIX") {
        PathBuf::from("/etc/hosts")
    } else {
        let mut path = match env::var("WINDIR") {
            Ok(dir) => PathBuf::from(dir),
            _ => return hosts,
        };
        path.push("/system32/drivers/etc/hosts");
        path
    };

    let _ = handle_every_line(&hosts_path,
                              &mut |line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.is_empty() {
            let ip = parts[0];
            if (prefer_ipv6 && is_ipv6(ip)) || (!prefer_ipv6 && is_ipv4(ip)) {
                for hostname in parts[1..].iter() {
                    if !hostname.is_empty() {
                        hosts.insert(hostname.to_string(), ip.to_string());
                    }
                }
            }
        }
    });

    hosts
}

// For detail, see page 7 of RFC 1035
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.len() > 255 {
        return false;
    }

    lazy_static! {
        static ref RE: Regex = Regex::new(r"[A-Za-z\d-]{1,63}$").unwrap();
    }

    let hostname = hostname.trim_right_matches('.');
    hostname.as_bytes()
        .split(|c| *c == b'.')
        .all(|s| {
            let s = slice2str(s).unwrap_or("");
            !s.is_empty() && !s.starts_with('-') && !s.ends_with('-') && RE.is_match(s)
        })
}

#[allow(dead_code, non_snake_case)]
mod QType {
    pub const A: u16 = 1;
    pub const AAAA: u16 = 28;
    pub const CNAME: u16 = 5;
    pub const NS: u16 = 2;
    pub const ANY: u16 = 255;
}

#[allow(dead_code, non_snake_case)]
mod QClass {
    pub const IN: u16 = 1;
}


#[cfg(test)]
mod test {
    use mio::Token;

    use asyncdns;

    const IPV4_TESTS: [(&'static str, &'static str); 3] = [("8.8.8.8", "8.8.8.8"),
                                                           ("localhost", "127.0.0.1"),
                                                           ("localhost.loggerhead.me",
                                                            "127.0.0.1")];

    const IPV6_TESTS: [(&'static str, &'static str); 3] = [("2001:4860:4860::8888",
                                                            "2001:4860:4860::8888"),
                                                           ("localhost", "::1"),
                                                           ("localhost.loggerhead.me", "::1")];

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn parse_response() {
        let data: &[u8] =
            &[0x0d, 0x0d, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00, 0x05, 0x62,
              0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
              0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0xb4, 0x95, 0x84,
              0x2f, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00, 0x04, 0xdc,
              0xb5, 0x39, 0xd9, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x36, 0x00,
              0x04, 0x6f, 0x0d, 0x65, 0xd0, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
              0x36, 0x00, 0x04, 0x7b, 0x7d, 0x72, 0x90, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00,
              0x01, 0x4f, 0x30, 0x00, 0x06, 0x03, 0x64, 0x6e, 0x73, 0xc0, 0x0c, 0xc0, 0x0c, 0x00,
              0x02, 0x00, 0x01, 0x00, 0x01, 0x4f, 0x30, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x37, 0xc0,
              0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x4f, 0x30, 0x00, 0x06, 0x03,
              0x6e, 0x73, 0x33, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x4f,
              0x30, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00,
              0x01, 0x00, 0x01, 0x4f, 0x30, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x0c];

        assert!(asyncdns::parse_response(data).is_some());
    }

    fn test_block_resolve(ipv6: bool) {
        let tests = if ipv6 { IPV6_TESTS } else { IPV4_TESTS };
        let mut resolver = asyncdns::DnsResolver::new(Token(0), None, ipv6).unwrap();
        for &(hostname, ip) in &tests {
            match resolver.block_resolve(hostname.to_string()) {
                Ok(r) => {
                    assert!(r.is_some());
                    let asyncdns::HostIpPair(_hostname, resolved_ip) = r.unwrap();
                    assert!(resolved_ip == ip);
                }
                Err(e) => {
                    println!("block_resolve failed: {:?}", e);
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn ipv4_block_resolve() {
        test_block_resolve(false);
    }

    // this test may failed if your computer is not a ipv6 host
    #[test]
    #[ignore]
    fn ipv6_block_resolve() {
        test_block_resolve(true);
    }
}
