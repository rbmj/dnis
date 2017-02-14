use super::{Name, Type};
use super::question::ToType;
use super::rr::{RRData, RRDataMap, SrvRecord, SoaRecord, MxRecord};
use std::net::{Ipv4Addr, Ipv6Addr};

pub use super::Class::{IN, CS, CH, HS};

pub struct CNAME;
impl RRDataMap for CNAME {
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
}
impl ToType for CNAME {
    fn to_type() -> Type {
        Type::CNAME
    }
}

pub struct NS;
impl RRDataMap for NS {
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
}
impl ToType for NS {
    fn to_type() -> Type {
        Type::NS
    }
}

pub struct PTR;
impl RRDataMap for PTR {
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
}
impl ToType for PTR {
    fn to_type() -> Type {
        Type::PTR
    }
}

pub struct A;
impl RRDataMap for A {
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
}
impl ToType for A {
    fn to_type() -> Type {
        Type::A
    }
}

pub struct AAAA;
impl RRDataMap for AAAA {
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
}
impl ToType for AAAA {
    fn to_type() -> Type {
        Type::AAAA
    }
}

pub struct SRV;
impl RRDataMap for SRV {
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
}
impl ToType for SRV {
    fn to_type() -> Type {
        Type::SRV
    }
}

pub struct SOA;
impl RRDataMap for SOA {
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
}
impl ToType for SOA {
    fn to_type() -> Type {
        Type::SOA
    }
}

pub struct MX;
impl RRDataMap for MX {
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
}
impl ToType for MX {
    fn to_type() -> Type {
        Type::MX
    }
}

pub struct TXT;
impl RRDataMap for TXT {
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
}
impl ToType for TXT {
    fn to_type() -> Type {
        Type::TXT
    }
}

pub struct Unknown;
impl RRDataMap for Unknown {
    type D = Vec<u8>;
    fn map(rrd: &RRData) -> Option<&Vec<u8>> {
        if let &RRData::Unknown(ref unk) = rrd {
            return Some(unk);
        }
        None
    }
    fn map_mut(rrd: &mut RRData) -> Option<&mut Vec<u8>> {
        if let &mut RRData::Unknown(ref mut unk) = rrd {
            return Some(unk);
        }
        None
    }
    fn unmap(unk: Vec<u8>) -> RRData {
        RRData::Unknown(unk)
    }
}

