/// Represents DNS query types.
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DnsQueryType {
    /// A record maps a domain name to an IPv4 address.
    A = 1,
    /// NS record maps a domain name to a name server.
    NS = 2,
    /// CNAME record maps a domain name to another domain (alias).
    CNAME = 5,
    /// SOA record provides administrative information.
    SOA = 6,
    /// PTR record maps an IP address to a domain name (reverse DNS).
    PTR = 12,
    /// MX record maps a domain name to a mail exchange server.
    MX = 15,
    /// TXT record provides arbitrary text for a domain name.
    TXT = 16,
    /// AAAA record maps a domain name to an IPv6 address.
    AAAA = 28,
    /// SRV record maps a domain name to a specific service.
    SRV = 33,
    /// Unknown query type with a specific numeric value.
    UNKNOWN(u16),
}

impl DnsQueryType {
    /// Converts a `u16` value into a `QueryType` enum.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            12 => Self::PTR,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            33 => Self::SRV,
            other => Self::UNKNOWN(other),
        }
    }

    /// Converts a `QueryType` enum into its corresponding `u16` value.
    pub fn to_u16(&self) -> u16 {
        match *self {
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::PTR => 12,
            Self::MX => 15,
            Self::TXT => 16,
            Self::AAAA => 28,
            Self::SRV => 33,
            Self::UNKNOWN(value) => value,
        }
    }
}

/// Represents DNS query classes.
#[repr(u16)]
#[derive(PartialEq, Eq, Debug)]
pub enum DnsQueryClass {
    /// Internet class (most common).
    IN = 1,
    /// Chaos class (experimental).
    CH = 3,
    /// Hesiod class (experimental).
    HS = 4,
    /// None class, used in certain updates.
    NONE = 254,
    /// Any class, used in wildcard queries.
    ANY = 255,
    /// Reserved for future use.
    RESERVED = 0,
    /// Reserved for private use.
    ReservedPrivate = 0xFF00,
    /// Unassigned values (default for others).
    UNASSIGNED,
}

impl DnsQueryClass {
    /// Converts a `u16` value into a `QueryClass` enum.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::IN,
            3 => Self::CH,
            4 => Self::HS,
            254 => Self::NONE,
            255 => Self::ANY,
            0 => Self::RESERVED,
            0xFF00..=0xFFFF => Self::ReservedPrivate,
            _ => Self::UNASSIGNED,
        }
    }

    /// Converts a `QueryClass` enum into its corresponding `u16` value.
    pub fn to_u16(&self) -> u16 {
        match *self {
            Self::IN => 1,
            Self::CH => 3,
            Self::HS => 4,
            Self::NONE => 254,
            Self::ANY => 255,
            Self::RESERVED => 0,
            Self::ReservedPrivate => 0xFF00,
            Self::UNASSIGNED => 0xFFFF,
        }
    }
}
