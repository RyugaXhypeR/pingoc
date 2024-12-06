use super::query::QueryClass;
use super::{buffer::PacketBuffer, query::QueryType};
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, PartialEq, Eq)]
pub enum Record {
    /// A (Address) record maps a domain to an IPv4 address
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    /// NS (Name Server) record maps a domain to a name server
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    /// CNAME (Canonical Name) record maps a domain to another domain
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    /// SOA (Start of Authority) record provides administrative information
    SOA {
        domain: String,
        primary_ns: String,
        mailbox: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum_ttl: u32,
        ttl: u32,
    },
    /// PTR (Pointer) record maps an IP address to a domain name (reverse DNS)
    PTR {
        domain: String,
        host: String,
        ttl: u32,
    },
    /// MX (Mail Exchange) record maps a domain to a mail server
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    /// TXT (Text) record provides arbitrary human-readable text for a domain
    TXT {
        domain: String,
        text: String,
        ttl: u32,
    },
    /// AAAA (IPv6 Address) record maps a domain to an IPv6 address
    AAAA {
        domain: String,
        addr: std::net::Ipv6Addr,
        ttl: u32,
    },
    /// SRV (Service Locator) record maps a domain to a specific service
    SRV {
        domain: String,
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
        ttl: u32,
    },
    /// Represents an unknown record type
    UNKNOWN {
        domain: String,
        query_type: QueryType,
        data: Vec<u8>,
        ttl: u32,
    },
}

impl Record {
    /* DNS Resource Record

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    */
    pub fn read(buffer: &mut PacketBuffer) -> Result<Record> {
        let domain = buffer.read_query_name()?;
        let query_type = QueryType::from_u16(buffer.read_u16()?);
        let _query_class = QueryClass::from_u16(buffer.read_u16()?);
        let ttl = buffer.read_u32()?;
        let length = buffer.read_u16()?;

        match query_type {
            QueryType::A => {
                let addr = Ipv4Addr::from(buffer.read_u32()?);
                Ok(Record::A { domain, addr, ttl })
            }
            QueryType::NS => {
                let host = buffer.read_query_name()?;
                Ok(Record::NS { domain, host, ttl })
            }
            QueryType::CNAME => {
                let host = buffer.read_query_name()?;
                Ok(Record::CNAME { domain, host, ttl })
            }
            QueryType::SOA => {
                let primary_ns = buffer.read_query_name()?;
                let mailbox = buffer.read_query_name()?;
                let serial = buffer.read_u32()?;
                let refresh = buffer.read_u32()?;
                let retry = buffer.read_u32()?;
                let expire = buffer.read_u32()?;
                let minimum_ttl = buffer.read_u32()?;
                Ok(Record::SOA {
                    domain,
                    primary_ns,
                    mailbox,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum_ttl,
                    ttl,
                })
            }
            QueryType::PTR => {
                let host = buffer.read_query_name()?;
                Ok(Record::PTR { domain, host, ttl })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let host = buffer.read_query_name()?;
                Ok(Record::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                })
            }
            QueryType::TXT => {
                let txt_data = buffer.read_bytes(length as usize)?;
                let text = String::from_utf8_lossy(txt_data).into_owned();
                Ok(Record::TXT { domain, text, ttl })
            }
            QueryType::AAAA => {
                let addr = Ipv6Addr::from(buffer.read_u128()?);
                Ok(Record::AAAA { domain, addr, ttl })
            }
            QueryType::SRV => {
                let priority = buffer.read_u16()?;
                let weight = buffer.read_u16()?;
                let port = buffer.read_u16()?;
                let target = buffer.read_query_name()?;
                Ok(Record::SRV {
                    domain,
                    priority,
                    weight,
                    port,
                    target,
                    ttl,
                })
            }
            _ => {
                let data = buffer.read_bytes(length as usize)?.to_vec();
                Ok(Record::UNKNOWN {
                    domain,
                    query_type,
                    data,
                    ttl,
                })
            }
        }
    }
    pub fn write(&self, buffer: &mut PacketBuffer) -> Result<()> {
        match self {
            Record::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::A.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(4)?;
                buffer.write_u32(u32::from(*addr))?;
            }
            Record::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::NS.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                let host_bytes = host.as_bytes();
                buffer.write_u16(host_bytes.len() as u16)?;
                buffer.write_bytes(host_bytes)?;
            }
            Record::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::CNAME.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                let host_bytes = host.as_bytes();
                buffer.write_u16(host_bytes.len() as u16)?;
                buffer.write_bytes(host_bytes)?;
            }
            Record::SOA {
                ref domain,
                ref primary_ns,
                ref mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum_ttl,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::SOA.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;

                buffer.write_query_name(primary_ns)?;
                buffer.write_query_name(mailbox)?;
                buffer.write_u32(*serial)?;
                buffer.write_u32(*refresh)?;
                buffer.write_u32(*retry)?;
                buffer.write_u32(*expire)?;
                buffer.write_u32(*minimum_ttl)?;
            }
            Record::PTR {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::PTR.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(host.len() as u16)?;
                buffer.write_bytes(host.as_bytes())?;
            }
            Record::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::MX.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(2)?;
                buffer.write_u16(*priority)?;
                buffer.write_query_name(host)?;
            }
            Record::TXT {
                ref domain,
                ref text,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::TXT.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                let txt_bytes = text.as_bytes();
                buffer.write_u16(txt_bytes.len() as u16)?;
                buffer.write_bytes(txt_bytes)?;
            }
            Record::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::AAAA.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(16)?;
                buffer.write_u128(u128::from(*addr))?;
            }
            Record::SRV {
                ref domain,
                priority,
                weight,
                port,
                ref target,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(QueryType::SRV.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(6)?;
                buffer.write_u16(*priority)?;
                buffer.write_u16(*weight)?;
                buffer.write_u16(*port)?;
                buffer.write_query_name(target)?;
            }
            Record::UNKNOWN {
                ref domain,
                query_type,
                ref data,
                ttl,
            } => {
                buffer.write_query_name(domain)?;
                buffer.write_u16(query_type.to_u16())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(data.len() as u16)?;
                buffer.write_bytes(data)?;
            }
        }
        Ok(())
    }
}
