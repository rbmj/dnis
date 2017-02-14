use std::fmt;
use std::str::FromStr;
use std::io::{Cursor, Write};
use byteorder::{BigEndian, WriteBytesExt};

use super::{Name, Error, Type, Class};
use dns_parser;

pub trait ToType {
    fn to_type() -> Type;
}

#[derive(Clone)]
pub struct Question {
    pub name: Name,
    pub prefer_unicast: bool,
    pub qtype: Type,
    pub qclass: Class
}

impl Question {
    pub fn new<T: ToType>(n: Name, c: Class) -> Self {
        Question{
            name: n,
            prefer_unicast: false, //true, but only actually used for mDNS
            qtype: T::to_type(),
            qclass: c
        }
    }
    pub fn new_str<T: ToType>(n: &str, c: Class) -> Result<Self, Error> {
        Ok(Self::new::<T>(try!(Name::from_str(n)), c))
    }

    pub fn to_string(&self) -> String {
        format!("{:?} {:?} {}", self.qclass, self.qtype, self.name)
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        try!(self.name.serialize(cursor));
        try!(cursor.write_u16::<BigEndian>(self.qtype as u16));
        let mut class = self.qclass as u16;
        if self.prefer_unicast { class |= 0x8000u16; }
        try!(cursor.write_u16::<BigEndian>(class));
        Ok(())
    }
    pub fn from_packet(q: &dns_parser::Question) -> Result<Self, Error> {
        let n = Name::from_string(q.qname.to_string())?;
        Ok(Question{
            name: n,
            prefer_unicast: q.prefer_unicast,
            qtype: Type::from(q.qtype),
            qclass: Class::from(q.qclass)
        })
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

