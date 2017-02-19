use dns_parser;

/// The QTYPE value according to RFC 1035
///
/// All "EXPERIMENTAL" markers here are from the RFC
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Type {
    /// a host addresss
    A,
    /// an authoritative name server
    NS,
    /// a mail forwarder (Obsolete - use MX)
    MF,
    /// the canonical name for an alias
    CNAME,
    /// marks the start of a zone of authority
    SOA,
    /// a mailbox domain name (EXPERIMENTAL)
    MB,
    /// a mail group member (EXPERIMENTAL)
    MG,
    /// a mail rename domain name (EXPERIMENTAL)
    MR,
    /// a null RR (EXPERIMENTAL)
    NULL,
    /// a well known service description
    WKS,
    /// a domain name pointer
    PTR,
    /// host information
    HINFO,
    /// mailbox or mail list information
    MINFO,
    /// mail exchange
    MX,
    /// text strings
    TXT,
    /// IPv6 host address (RFC 2782)
    AAAA,
    /// service record (RFC 2782)
    SRV,
    /// EDNS0 options (RFC 6891)
    OPT,
    /// A request for a transfer of an entire zone
    AXFR,
    /// A request for mailbox-related records (MB, MG or MR)
    MAILB,
    /// A request for mail agent RRs (Obsolete - see MX)
    MAILA,
    /// A request for all records
    All,
    /// Unknown Type
    Unknown(u16)
}

impl Into<u16> for Type {
    fn into(self) -> u16 {
        use self::Type::*;
        match self {
            A => 1,
            NS => 2,
            MF => 4,
            CNAME => 5,
            SOA => 6,
            MB => 7,
            MG => 8,
            MR => 9,
            NULL => 10,
            WKS => 11,
            PTR => 12,
            HINFO => 13,
            MINFO => 14,
            MX => 15,
            TXT => 16,
            AAAA => 28,
            SRV => 33,
            OPT => 41,
            AXFR => 252,
            MAILB => 253,
            MAILA => 254,
            All => 255,
            Unknown(x) => x
        }
    }
}

impl From<u16> for Type {
    fn from(code: u16) -> Type {
        use Type::*;
        match code {
            1 => A,
            2 => NS,
            4 => MF,
            5 => CNAME,
            6 => SOA,
            7 => MB,
            8 => MG,
            9 => MR,
            10 => NULL,
            11 => WKS,
            12 => PTR,
            13 => HINFO,
            14 => MINFO,
            15 => MX,
            16 => TXT,
            28 => AAAA,
            33 => SRV,
            41 => OPT,
            252 => AXFR,
            253 => MAILB,
            254 => MAILA,
            255 => All,
            x => Unknown(x)
        }
    }
}

/// The QCLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Class {
    /// the Internet
    IN,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS,
    /// the CHAOS class
    CH,
    /// Hesiod [Dyer 87]
    HS,
    /// Any class
    Any,
    /// Unknown Class
    Unknown(u16)
}

impl From<u16> for Class {
    fn from(code: u16) -> Class {
        use self::Class::*;
        match code {
            1 => IN,
            2 => CS,
            3 => CH,
            4 => HS,
            255 => Any,
            x => Unknown(x)
        }
    }
}

impl Into<u16> for Class {
    fn into(self) -> u16 {
        use self::Class::*;
        match self {
            IN => 1,
            CS => 2,
            CH => 3,
            HS => 4,
            Any => 255,
            Unknown(x) => x
        }
    }
}


impl From<dns_parser::QueryClass> for Class {
    fn from(qc: dns_parser::QueryClass) -> Class {
        use self::Class::*;
        match qc {
            dns_parser::QueryClass::IN => IN,
            dns_parser::QueryClass::CS => CS,
            dns_parser::QueryClass::CH => CH,
            dns_parser::QueryClass::HS => HS,
            dns_parser::QueryClass::Any => Any
        }
    }
}
impl From<dns_parser::Class> for Class {
    fn from(qc: dns_parser::Class) -> Class {
        use self::Class::*;
        match qc {
            dns_parser::Class::IN => IN,
            dns_parser::Class::CS => CS,
            dns_parser::Class::CH => CH,
            dns_parser::Class::HS => HS,
        }
    }
}


impl From<dns_parser::QueryType> for Type {
    fn from(qt: dns_parser::QueryType) -> Type {
        use self::Type::*;
        match qt {
            dns_parser::QueryType::A => A,
            dns_parser::QueryType::NS => NS,
            dns_parser::QueryType::MF => MF,
            dns_parser::QueryType::CNAME => CNAME,
            dns_parser::QueryType::SOA => SOA,
            dns_parser::QueryType::MB => MB,
            dns_parser::QueryType::MG => MG,
            dns_parser::QueryType::MR => MR,
            dns_parser::QueryType::NULL => NULL,
            dns_parser::QueryType::WKS => WKS,
            dns_parser::QueryType::PTR => PTR,
            dns_parser::QueryType::HINFO => HINFO,
            dns_parser::QueryType::MINFO => MINFO,
            dns_parser::QueryType::MX => MX,
            dns_parser::QueryType::TXT => TXT,
            dns_parser::QueryType::AAAA => AAAA,
            dns_parser::QueryType::SRV => SRV,
            dns_parser::QueryType::AXFR => AXFR,
            dns_parser::QueryType::MAILB => MAILB,
            dns_parser::QueryType::MAILA => MAILA,
            dns_parser::QueryType::All => All,
        }
    }
}
impl From<dns_parser::Type> for Type {
    fn from(qt: dns_parser::Type) -> Type {
        use self::Type::*;
        match qt {
            dns_parser::Type::A => A,
            dns_parser::Type::NS => NS,
            dns_parser::Type::MF => MF,
            dns_parser::Type::CNAME => CNAME,
            dns_parser::Type::SOA => SOA,
            dns_parser::Type::MB => MB,
            dns_parser::Type::MG => MG,
            dns_parser::Type::MR => MR,
            dns_parser::Type::NULL => NULL,
            dns_parser::Type::WKS => WKS,
            dns_parser::Type::PTR => PTR,
            dns_parser::Type::HINFO => HINFO,
            dns_parser::Type::MINFO => MINFO,
            dns_parser::Type::MX => MX,
            dns_parser::Type::TXT => TXT,
            dns_parser::Type::AAAA => AAAA,
            dns_parser::Type::SRV => SRV,
            dns_parser::Type::OPT => OPT
        }
    }
}

/// The OPCODE value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Opcode {
    StandardQuery,
    InverseQuery,
    ServerStatusRequest,
    Reserved(u16),
}

/// The RCODE value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(u16),
}

impl From<u16> for Opcode {
    fn from(code: u16) -> Opcode {
        use self::Opcode::*;
        match code {
            0 => StandardQuery,
            1 => InverseQuery,
            2 => ServerStatusRequest,
            x => Reserved(x),
        }
    }
}
impl Into<u16> for Opcode {
    fn into(self) -> u16 {
        use self::Opcode::*;
        match self {
            StandardQuery => 0,
            InverseQuery => 1,
            ServerStatusRequest => 2,
            Reserved(x) => x,
        }
    }
}

impl From<u16> for ResponseCode {
    fn from(code: u16) -> ResponseCode {
        use self::ResponseCode::*;
        match code {
            0      => NoError,
            1      => FormatError,
            2      => ServerFailure,
            3      => NameError,
            4      => NotImplemented,
            5      => Refused,
            6...15 => Reserved(code),
            x => panic!("Invalid response code {}", x),
        }
    }
}
impl Into<u16> for ResponseCode {
    fn into(self) -> u16 {
        use self::ResponseCode::*;
        match self {
            NoError => 0,
            FormatError => 1,
            ServerFailure => 2,
            NameError => 3,
            NotImplemented => 4,
            Refused => 5,
            Reserved(code) => code,
        }
    }
}
    
