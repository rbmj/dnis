use std::fmt;
use std::str::FromStr;
use std::io::{Cursor, Write, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};

use super::{Name, Error, Class, Type};
use dns_parser;

#[derive(Clone)]
pub struct ResourceRecord {
    pub name: Name,
    pub multicast_unique: bool,
    pub class: Class,
    pub ttl: u32,
    pub data: RRData
}

#[derive(Clone)]
pub struct OptRecord {
    pub udp: u16,
    pub extrcode: u8,
    pub version: u8,
    pub flags: u16,
    pub data: Vec<u8>
}

#[derive(Clone)]
pub struct SoaRecord {
    pub primary_ns: Name,
    pub mailbox: Name,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub min_ttl: u32
}

#[derive(Clone)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: Name
}

#[derive(Clone)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: Name
}

#[derive(Clone)]
pub struct UnknownRecord {
    pub typecode: u16,
    pub data: Vec<u8>
}

#[derive(Clone)]
pub enum RRData {
    CNAME(Name),
    NS(Name),
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    SRV(SrvRecord),
    SOA(SoaRecord),
    PTR(Name),
    MX(MxRecord),
    TXT(Vec<u8>),
    Unknown(UnknownRecord)
}

macro_rules! map_rrtype {
    ($t:ident, $func:ident $call:tt) => {
        match $t {
            Type::A => super::types::A::$func $call,
            Type::AAAA => super::types::AAAA::$func $call,
            Type::CNAME => super::types::CNAME::$func $call,
            Type::MX => super::types::MX::$func $call,
            Type::NS => super::types::NS::$func $call,
            Type::PTR => super::types::PTR::$func $call,
            Type::SOA => super::types::SOA::$func $call,
            Type::SRV => super::types::SRV::$func $call,
            Type::TXT => super::types::TXT::$func $call,
            _ => super::types::Unknown::$func $call
        }
    }
}

pub trait RRType {
    type D;
    fn map(&RRData) -> Option<&Self::D>;
    fn map_mut(&mut RRData) -> Option<&mut Self::D>;
    fn unmap(Self::D) -> RRData;
    fn to_type() -> Type;
    fn to_type_data(_: &RRData) -> Result<Type, Error> {
        Ok(Self::to_type())
    }
    fn serialize<T>(&Self::D, &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T> : Write;
    fn parse<T>(&mut Cursor<T>, u16) -> Result<Self::D, Error>
        where Cursor<T> : Read;
    fn serialize_data<T>(d: &RRData, c: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T> : Write
    {
        Self::serialize(Self::map(d).ok_or(Error::ParserStateError)?, c)
    }
    fn parse_data<T>(c: &mut Cursor<T>, l: u16) -> Result<RRData, Error>
        where Cursor<T> : Read
    {
        Self::parse(c, l).map(Self::unmap)
    }
}

#[derive(Debug)]
pub enum RRError<T> {
    DNS(Error),
    DataConv(T)
}

pub enum ResourceRecordAddl {
    RR(ResourceRecord),
    OPT(OptRecord)
}

impl ResourceRecord {
    pub fn get_type(&self) -> Type {
        match &self.data {
            &RRData::CNAME(_) => Type::CNAME,
            &RRData::NS(_) => Type::NS,
            &RRData::A(_) => Type::A,
            &RRData::AAAA(_) => Type::AAAA,
            &RRData::SRV(_) => Type::SRV,
            &RRData::SOA(_) => Type::SOA,
            &RRData::PTR(_) => Type::PTR,
            &RRData::MX(_) => Type::MX,
            &RRData::TXT(_) => Type::TXT,
            &RRData::Unknown(ref x) => return Type::Unknown(x.typecode)
        }
    }
    pub fn is<T: RRType>(&self) -> bool {
        T::map(&self.data).is_some()
    }
    pub fn get<T: RRType>(&self) -> Option<&T::D> {
        T::map(&self.data)
    }
    pub fn get_mut<T: RRType>(&mut self) -> Option<&mut T::D> {
        T::map_mut(&mut self.data)
    }
    pub fn new<T: RRType>(n: Name, c: Class, d: T::D) -> Self {
        //a lot of the time the TTL is ignored so we just set a sane default
        Self::new_ttl::<T>(n, 60, c, d)
    }
    pub fn new_ttl<T: RRType>(n: Name, ttl: u32, c: Class, d: T::D) -> Self {
        ResourceRecord {
            name: n,
            multicast_unique: false, //only set in mDNS
            class: c,
            ttl: ttl,
            data: T::unmap(d)
        }
    }
    pub fn new_str<T>(n: &str, c: Class, d: &str)
        -> Result<Self, RRError<<<T as RRType>::D as FromStr>::Err>>
        where T: RRType, T::D: FromStr
    {
        //a lot of the time the TTL is ignored so we just set a sane default
        Self::new_str_ttl::<T>(n, 60, c, d)
    }
    pub fn new_str_ttl<T>(n: &str, ttl: u32, c: Class, d: &str)
        -> Result<Self, RRError<<<T as RRType>::D as FromStr>::Err>>
        where T: RRType, T::D: FromStr
    {
        let name = try!(Name::from_str(n).map_err(RRError::DNS));
        let data = try!(T::D::from_str(d).map_err(RRError::DataConv));
        Ok(Self::new_ttl::<T>(name, ttl, c, data))
    }
    pub fn parse<T>(cursor: &mut Cursor<T>) -> Result<Self, Error>
        where Cursor<T> : Read
    {
        let n = Name::parse(cursor)?;
        let t = Type::from(cursor.read_u16::<BigEndian>()?);
        if t == Type::OPT {
            //this shouldn't be here!
            return Err(Error::InvalidOpt);
        }
        let c = cursor.read_u16::<BigEndian>()?;
        let ttl = cursor.read_u32::<BigEndian>()?;
        let datalen = cursor.read_u16::<BigEndian>()?;
        let mut data = map_rrtype!(t, parse_data(cursor, datalen))?;
        if let RRData::Unknown(ref mut x) = data {
            x.typecode = t.into();
        }
        Ok(ResourceRecord {
            name: n,
            multicast_unique: false,
            class: Class::from(c),
            ttl: ttl,
            data: data
        })
    }
    pub fn parse_additional<T>(cursor: &mut Cursor<T>) -> Result<ResourceRecordAddl, Error>
        where Cursor<T> : Read
    {
        let pos = cursor.position();
        let dat = cursor.read_u32::<BigEndian>()?;
        let opt_t : u16 = Type::OPT.into();
        if dat >> 8 != opt_t as u32 {
            //first byte must be 00, second two bytes must be OPT type code
            cursor.set_position(pos);
            return Ok(ResourceRecordAddl::RR(Self::parse(cursor)?));
        }
        let mut udp = (dat & 0xFF) as u16;
        udp = (udp << 8) | (cursor.read_u8()? as u16);
        let extrcode = cursor.read_u8()?;
        let version = cursor.read_u8()?;
        let flags = cursor.read_u16::<BigEndian>()?;
        let datalen = cursor.read_u16::<BigEndian>()?;
        let mut buf = vec![0u8; datalen as usize];
        cursor.read_exact(&mut buf[..])?;
        Ok(ResourceRecordAddl::OPT(OptRecord{
            udp: udp,
            extrcode: extrcode,
            version: version,
            flags: flags,
            data: buf
        }))
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        try!(self.name.serialize(cursor));
        try!(cursor.write_u16::<BigEndian>(self.data.get_typenum()));
        let mut class : u16 = self.class.into();
        if self.multicast_unique { class |= 0x8000; }
        try!(cursor.write_u16::<BigEndian>(class));
        try!(cursor.write_u32::<BigEndian>(self.ttl));
        try!(self.data.serialize(cursor));
        Ok(())
    }
    pub fn from_packet(rr: &dns_parser::ResourceRecord) -> Result<Self, Error> {
        let n = Name::from_string(rr.name.to_string())?;
        Ok(ResourceRecord{
            name: n,
            multicast_unique: rr.multicast_unique,
            class: Class::from(rr.cls),
            ttl: rr.ttl,
            data: RRData::from_packet(&rr.data)?
        })
    }
    
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //FIXME: optionally include TTL
        match &self.data {
            &RRData::CNAME(ref n) => write!(f, "{} {:?} CNAME {}", self.name,
                self.class, n),
            &RRData::NS(ref n) => write!(f, "{} {:?} NS {}", self.name,
                self.class, n),
            &RRData::A(ref a) => write!(f, "{} {:?} A {}", self.name,
                self.class, a),
            &RRData::AAAA(ref a) => write!(f, "{} {:?} AAAA {}", self.name,
                self.class, a),
            &RRData::SRV(ref rec) => write!(f, "{} {:?} SRV {} {} {} {}",
                self.name, self.class, rec.priority, rec.weight,
                rec.port, rec.target),
            &RRData::SOA(ref rec) => write!(f,
                "{} {:?} SOA {} {} ({} {} {} {} {})", self.name,
                self.class, rec.primary_ns, rec.mailbox, rec.serial,
                rec.refresh, rec.retry, rec.expire, rec.min_ttl),
            &RRData::PTR(ref n) => write!(f, "{} {:?} PTR {}", self.name,
                self.class, n),
            &RRData::MX(ref rec) => write!(f, "{} {:?} MX {} {}", self.name,
                self.class, rec.preference, rec.exchange),
            &RRData::TXT(ref v) => write!(f, "{} {:?} TXT \"{}\"", self.name,
                self.class, String::from_utf8_lossy(&v[..])),
            &RRData::Unknown(ref v) => {
                write!(f, "{} {:?} <UNKNOWN> [", self.name, self.class)?;
                let mut first = true;
                for byte in &v.data {
                    if !first { write!(f, ", ")?; }
                    else { first = false; }
                    write!(f, "{:X}", byte)?;
                }
                write!(f, "]")
            }
        }
    }
}

impl OptRecord {
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T> : Write
    {
        cursor.write_u8(0)?;
        cursor.write_u16::<BigEndian>(41)?; //OPT magic number
        cursor.write_u16::<BigEndian>(self.udp)?;
        cursor.write_u8(self.extrcode)?;
        cursor.write_u8(self.version)?;
        cursor.write_u16::<BigEndian>(self.flags)?;
        cursor.write_all(&self.data[..])?;
        Ok(())
    }
    pub fn from_packet(rr: &dns_parser::OptRecord) -> Result<Self, Error> {
        Ok(OptRecord{
            udp: rr.udp,
            extrcode: rr.extrcode,
            version: rr.version,
            flags: rr.flags,
            data: Vec::<u8>::new()}) //FIXME
    }
}

impl RRData {
    fn get_typenum(&self) -> u16 {
        match *self {
                RRData::CNAME(_) => 5,
                RRData::NS(_) => 2,
                RRData::A(_) => 1,
                RRData::AAAA(_) => 28,
                RRData::SRV(_) => 33,
                RRData::SOA(_) => 6,
                RRData::PTR(_) => 12,
                RRData::MX(_) => 15,
                RRData::TXT(_) => 16,
                RRData::Unknown(ref x) => x.typecode
        }
    }
    fn from_packet(rrd: &dns_parser::RRData) -> Result<Self, Error> {
        let ret = match *rrd {
            dns_parser::RRData::CNAME(ref n) => RRData::CNAME(Name::from_string(n.to_string())?),
            dns_parser::RRData::NS(ref n) => RRData::NS(Name::from_string(n.to_string())?),
            dns_parser::RRData::A(ref a) => RRData::A(a.clone()),
            dns_parser::RRData::AAAA(ref a) => RRData::AAAA(a.clone()),
            dns_parser::RRData::SRV{priority, weight, port, target} =>
                RRData::SRV(SrvRecord{
                    priority: priority,
                    weight:  weight,
                    port: port,
                    target: Name::from_string(target.to_string())?}),
            dns_parser::RRData::SOA(ref rec) => RRData::SOA(SoaRecord{
                primary_ns: Name::from_string(rec.primary_ns.to_string())?,
                mailbox: Name::from_string(rec.mailbox.to_string())?,
                serial: rec.serial,
                refresh: rec.refresh,
                retry: rec.retry,
                expire: rec.expire,
                min_ttl: rec.minimum_ttl}),
            dns_parser::RRData::PTR(ref n) => RRData::PTR(Name::from_string(n.to_string())?),
            dns_parser::RRData::MX{preference: pref, exchange: ex} => RRData::MX(MxRecord{
                preference: pref,
                exchange: Name::from_string(ex.to_string())?}),
            dns_parser::RRData::Unknown(ref v) => RRData::Unknown(UnknownRecord{typecode: 0, data: v.iter().map(|x| *x).collect()}) //FIXME: Smell
        };
        Ok(ret)
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        use super::types::*;
        try!(cursor.write_u16::<BigEndian>(0));
        let pos = cursor.position();
        match self {
            &RRData::CNAME(ref x) => CNAME::serialize(x, cursor)?,
            &RRData::NS(ref x) => NS::serialize(x, cursor)?,
            &RRData::A(ref x) => A::serialize(x, cursor)?,
            &RRData::AAAA(ref x) => AAAA::serialize(x, cursor)?,
            &RRData::SRV(ref x) => SRV::serialize(x, cursor)?,
            &RRData::SOA(ref x) => SOA::serialize(x, cursor)?,
            &RRData::PTR(ref x) => PTR::serialize(x, cursor)?,
            &RRData::MX(ref x) => MX::serialize(x, cursor)?,
            &RRData::TXT(ref x) => cursor.write_all(&x[..])?,
            &RRData::Unknown(ref x) => cursor.write_all(&x.data[..])?
        }
        let endpos = cursor.position();
        cursor.set_position(pos-2);
        cursor.write_u16::<BigEndian>((endpos - pos) as u16)?;
        cursor.set_position(endpos);
        Ok(())
    }
}

