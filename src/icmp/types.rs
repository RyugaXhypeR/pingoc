use std::net::Ipv4Addr;

pub enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    TimeExceeded = 11,
    ParameterProblem = 12,
    TimestampRequest = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
    Unknown,
}

impl IcmpType {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::EchoReply => 0,
            Self::DestinationUnreachable => 3,
            Self::SourceQuench => 4,
            Self::Redirect => 5,
            Self::EchoRequest => 8,
            Self::TimeExceeded => 11,
            Self::ParameterProblem => 12,
            Self::TimestampRequest => 13,
            Self::TimestampReply => 14,
            Self::InformationRequest => 15,
            Self::InformationReply => 16,
            Self::Unknown => 17,
        }
    }

    pub fn from_u8(icmp_type: u8) -> Self {
        match icmp_type {
            0 => Self::EchoReply,
            3 => Self::DestinationUnreachable,
            4 => Self::SourceQuench,
            5 => Self::Redirect,
            8 => Self::EchoRequest,
            11 => Self::TimeExceeded,
            12 => Self::ParameterProblem,
            13 => Self::TimestampRequest,
            14 => Self::TimestampReply,
            15 => Self::InformationRequest,
            16 => Self::InformationReply,
            _ => Self::Unknown,
        }
    }
}

pub enum IcmpContentType {
    Echo {
        id: u16,
        sequence_no: u16,
    },
    DestinationUnreachable {
        unused: u32,
    },
    TimeExceeded {
        unused: u32,
    },
    ParameterProblem {
        pointer: u8,
        unused: u32, /* 24 bytes */
    },
    SourceQuench {
        unused: u32,
    },
    Redirect {
        gateway_address: Ipv4Addr,
    },
    Timestamp {
        id: u16,
        sequence_no: u16,
    },
    Information {
        id: u16,
        sequence_no: u16,
    },
}

impl IcmpContentType {
    pub fn to_be_bytes(&self) -> Vec<u8> {
        match *self {
            Self::Echo { id, sequence_no }
            | Self::Timestamp { id, sequence_no }
            | Self::Information { id, sequence_no } => {
                let combined = ((id as u32) << 16) | sequence_no as u32;
                combined.to_be_bytes().to_vec()
            }
            Self::DestinationUnreachable { unused }
            | Self::TimeExceeded { unused }
            | Self::SourceQuench { unused } => unused.to_be_bytes().to_vec(),
            Self::Redirect { gateway_address } => gateway_address.octets().to_vec(),
            Self::ParameterProblem { pointer, unused } => {
                let combined = ((pointer as u32) << 24) | (unused & 0xFFFFFF);
                combined.to_be_bytes().to_vec()
            }
        }
    }
}
