use super::{Name, Type, RRType, Error};
use super::rr::{RRData, SrvRecord, SoaRecord, MxRecord, UnknownRecord};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::io::{Read, Write, Cursor};
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

pub use super::Class::{IN, CS, CH, HS};

pub struct CNAME;
impl RRType for CNAME {
    type D = Name;
    fn map(rrd: &RRData) -> Option<&Name> {
        if let &RRData::CNAME(ref n) = rrd {
            return Some(n);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut Name> {
        if let &mut RRData::CNAME(ref mut n) = rrd {
            return Some(n);
        }
        None
    }
    fn unmap(n: Name) -> RRData {
        RRData::CNAME(n)
    }
    fn to_type() -> Type {
        Type::CNAME
    }
    fn parse<T>(cursor: &mut Cursor<T>, _: u16) -> Result<Name, Error>
        where Cursor<T>: Read
    {
        Name::parse(cursor)
    }
    fn serialize<T>(n: &Name, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T>: Write
    {
        n.serialize(cursor)
    }
}

pub struct NS;
impl RRType for NS {
    type D = Name;
    fn map(rrd: &RRData) -> Option<&Name> {
        if let &RRData::NS(ref n) = rrd {
            return Some(n);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut Name> {
        if let &mut RRData::NS(ref mut n) = rrd {
            return Some(n);
        }
        None
    }
    fn unmap(n: Name) -> RRData {
        RRData::NS(n)
    }
    fn to_type() -> Type {
        Type::NS
    }
    fn parse<T>(cursor: &mut Cursor<T>, _: u16) -> Result<Name, Error>
        where Cursor<T>: Read
    {
        Name::parse(cursor)
    }
    fn serialize<T>(n: &Name, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T>: Write
    {
        n.serialize(cursor)
    }
}

pub struct PTR;
impl RRType for PTR {
    type D = Name;
    fn map(rrd: &RRData) -> Option<&Name> {
        if let &RRData::PTR(ref n) = rrd {
            return Some(n);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut Name> {
        if let &mut RRData::PTR(ref mut n) = rrd {
            return Some(n);
        }
        None
    }
    fn unmap(n: Name) -> RRData {
        RRData::PTR(n)
    }
    fn to_type() -> Type {
        Type::PTR
    }
    fn parse<T>(cursor: &mut Cursor<T>, _: u16) -> Result<Name, Error>
        where Cursor<T>: Read
    {
        Name::parse(cursor)
    }
    fn serialize<T>(n: &Name, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T>: Write
    {
        n.serialize(cursor)
    }
}

pub struct A;
impl RRType for A {
    type D = Ipv4Addr;
    fn map(rrd: &RRData) -> Option<&Ipv4Addr> {
        if let &RRData::A(ref addr) = rrd {
            return Some(addr);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut Ipv4Addr> {
        if let &mut RRData::A(ref mut addr) = rrd {
            return Some(addr);
        }
        None
    }
    fn unmap(a: Ipv4Addr) -> RRData {
        RRData::A(a)
    }
    fn to_type() -> Type {
        Type::A
    }
    fn parse<T>(cursor: &mut Cursor<T>, _: u16) -> Result<Ipv4Addr, Error>
        where Cursor<T>: Read
    {
        let a = cursor.read_u8()?;
        let b = cursor.read_u8()?;
        let c = cursor.read_u8()?;
        let d = cursor.read_u8()?;
        Ok(Ipv4Addr::new(a, b, c, d))
    }
    fn serialize<T>(addr: &Ipv4Addr, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T>: Write
    {
        cursor.write_all(&addr.octets()[..])?;
        Ok(())
    }
}

pub struct AAAA;
impl RRType for AAAA {
    type D = Ipv6Addr;
    fn map(rrd: &RRData) -> Option<&Ipv6Addr> {
        if let &RRData::AAAA(ref addr) = rrd {
            return Some(addr);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut Ipv6Addr> {
        if let &mut RRData::AAAA(ref mut addr) = rrd {
            return Some(addr);
        }
        None
    }
    fn unmap(a: Ipv6Addr) -> RRData {
        RRData::AAAA(a)
    }
    fn to_type() -> Type {
        Type::AAAA
    }
    fn parse<T>(cursor: &mut Cursor<T>, _: u16) -> Result<Ipv6Addr, Error>
        where Cursor<T>: Read
    {
        let a = cursor.read_u16::<BigEndian>()?;
        let b = cursor.read_u16::<BigEndian>()?;
        let c = cursor.read_u16::<BigEndian>()?;
        let d = cursor.read_u16::<BigEndian>()?;
        let e = cursor.read_u16::<BigEndian>()?;
        let f = cursor.read_u16::<BigEndian>()?;
        let g = cursor.read_u16::<BigEndian>()?;
        let h = cursor.read_u16::<BigEndian>()?;
        Ok(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }
    fn serialize<T>(addr: &Ipv6Addr, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T>: Write
    {
        for seg in &addr.segments() {
            cursor.write_u16::<BigEndian>(*seg)?;
        }
        Ok(())
    }
}

pub struct SRV;
impl RRType for SRV {
    type D = SrvRecord;
    fn map(rrd: &RRData) -> Option<&SrvRecord> {
        if let &RRData::SRV(ref srv) = rrd {
            return Some(srv);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut SrvRecord> {
        if let &mut RRData::SRV(ref mut srv) = rrd {
            return Some(srv);
        }
        None
    }
    fn unmap(srv: SrvRecord) -> RRData {
        RRData::SRV(srv)
    }
    fn to_type() -> Type {
        Type::SRV
    }
    fn parse<T>(cursor: &mut Cursor<T>, _: u16) -> Result<SrvRecord, Error>
        where Cursor<T> : Read
    {
        let priority = cursor.read_u16::<BigEndian>()?;
        let weight = cursor.read_u16::<BigEndian>()?;
        let port = cursor.read_u16::<BigEndian>()?;
        let target = Name::parse(cursor)?;
        Ok(SrvRecord{
            priority: priority,
            weight: weight,
            port: port,
            target: target
        })
    }
    fn serialize<T>(srv: &SrvRecord, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T>: Write
    {
        cursor.write_u16::<BigEndian>(srv.priority)?;
        cursor.write_u16::<BigEndian>(srv.weight)?;
        cursor.write_u16::<BigEndian>(srv.port)?;
        srv.target.serialize(cursor)?;
        Ok(())
    }
}

pub struct SOA;
impl RRType for SOA {
    type D = SoaRecord;
    fn map(rrd: &RRData) -> Option<&SoaRecord> {
        if let &RRData::SOA(ref soa) = rrd {
            return Some(soa);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut SoaRecord> {
        if let &mut RRData::SOA(ref mut soa) = rrd {
            return Some(soa);
        }
        None
    }
    fn unmap(soa: SoaRecord) -> RRData {
        RRData::SOA(soa)
    }
    fn to_type() -> Type {
        Type::SOA
    }
    fn parse<T>(cursor: &mut Cursor<T>, _: u16) -> Result<SoaRecord, Error>
        where Cursor<T>: Read
    {
        let pri = Name::parse(cursor)?;
        let mail = Name::parse(cursor)?;
        let serial = cursor.read_u32::<BigEndian>()?;
        let refresh = cursor.read_u32::<BigEndian>()?;
        let retry = cursor.read_u32::<BigEndian>()?;
        let expire = cursor.read_u32::<BigEndian>()?;
        let min_ttl = cursor.read_u32::<BigEndian>()?;
        Ok(SoaRecord {
            primary_ns: pri,
            mailbox: mail,
            serial: serial,
            refresh: refresh,
            retry: retry,
            expire: expire,
            min_ttl: min_ttl
        })
    }
    fn serialize<T>(soa: &SoaRecord, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T>: Write
    {
        soa.primary_ns.serialize(cursor)?;
        soa.mailbox.serialize(cursor)?;
        cursor.write_u32::<BigEndian>(soa.serial)?;
        cursor.write_u32::<BigEndian>(soa.refresh)?;
        cursor.write_u32::<BigEndian>(soa.retry)?;
        cursor.write_u32::<BigEndian>(soa.expire)?;
        cursor.write_u32::<BigEndian>(soa.min_ttl)?;
        Ok(())
    }
}

pub struct MX;
impl RRType for MX {
    type D = MxRecord;
    fn map(rrd: &RRData) -> Option<&MxRecord> {
        if let &RRData::MX(ref mx) = rrd {
            return Some(mx);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut MxRecord> {
        if let &mut RRData::MX(ref mut mx) = rrd {
            return Some(mx);
        }
        None
    }
    fn unmap(mx: MxRecord) -> RRData {
        RRData::MX(mx)
    }
    fn to_type() -> Type {
        Type::MX
    }
    fn parse<T>(cursor: &mut Cursor<T>, _: u16) -> Result<MxRecord, Error>
        where Cursor<T>: Read
    {
        let pref = cursor.read_u16::<BigEndian>()?;
        Ok(MxRecord {
            preference: pref,
            exchange: Name::parse(cursor)?
        })
    }
    fn serialize<T>(mx: &MxRecord, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T>: Write
    {
        cursor.write_u16::<BigEndian>(mx.preference)?;
        mx.exchange.serialize(cursor)?;
        Ok(())
    }
}

pub struct TXT;
impl RRType for TXT {
    type D = Vec<u8>;
    fn map(rrd: &RRData) -> Option<&Vec<u8>> {
        if let &RRData::TXT(ref txt) = rrd {
            return Some(txt);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut Vec<u8>> {
        if let &mut RRData::TXT(ref mut txt) = rrd {
            return Some(txt);
        }
        None
    }
    fn unmap(txt: Vec<u8>) -> RRData {
        RRData::TXT(txt)
    }
    fn to_type() -> Type {
        Type::TXT
    }
    fn parse<T>(cursor: &mut Cursor<T>, len: u16) -> Result<Vec<u8>, Error>
        where Cursor<T> : Read
    {
        let mut buf = vec![0u8; len as usize];
        cursor.read_exact(&mut buf[..])?;
        Ok(buf)
    }
    fn serialize<T>(txt: &Vec<u8>, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T> : Write
    {
        cursor.write_all(txt)?;
        Ok(())
    }
}

pub struct Unknown;
impl RRType for Unknown {
    type D = UnknownRecord;
    fn map(rrd: &RRData) -> Option<&UnknownRecord> {
        if let &RRData::Unknown(ref unk) = rrd {
            return Some(unk);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut UnknownRecord> {
        if let &mut RRData::Unknown(ref mut unk) = rrd {
            return Some(unk);
        }
        None
    }
    fn unmap(unk: UnknownRecord) -> RRData {
        RRData::Unknown(unk)
    }
    fn to_type() -> Type {
        panic!("Getting type of unknown type")
    }
    fn to_type_data(rrd: &RRData) -> Result<Type, Error> {
        Ok(Type::Unknown(Self::map(rrd).ok_or(Error::ParserStateError)?.typecode))
    }
    fn parse<T>(cursor: &mut Cursor<T>, len: u16) -> Result<UnknownRecord, Error>
        where Cursor<T> : Read
    {
        let mut buf = vec![0u8; len as usize];
        cursor.read_exact(&mut buf[..])?;
        //typecode will get filled in by parent
        Ok(UnknownRecord{typecode: 0, data: buf})
    }
    fn serialize<T>(rec: &UnknownRecord, cursor: &mut Cursor<T>) -> Result<(), Error>
        where Cursor<T> : Write
    {
        cursor.write_all(&rec.data[..])?;
        Ok(())
    }
}

