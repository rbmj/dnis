use std::fmt;
use std::str::FromStr;
use std::io::{Cursor, Write, Read};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};

use super::{Name, Error, Type, Class};
use super::RRType;

#[derive(Clone)]
pub struct Question {
    pub qname: Name,
    pub prefer_unicast: bool,
    pub qtype: Type,
    pub qclass: Class
}

impl Question {
    pub fn new<T: RRType>(n: Name, c: Class) -> Self {
        Question{
            qname: n,
            prefer_unicast: false, //true, but only actually used for mDNS
            qtype: T::to_type(),
            qclass: c
        }
    }
    pub fn new_str<T: RRType>(n: &str, c: Class) -> Result<Self, Error> {
        Ok(Self::new::<T>(try!(Name::from_str(n)), c))
    }
    pub fn name(&self) -> &Name {
        &self.qname
    }
    pub fn is<T: RRType>(&self) -> bool {
        T::to_type() == self.qtype
    }
    pub fn class(&self) -> Class {
        self.qclass
    }
    pub fn to_string(&self) -> String {
        format!("{:?} {:?} {}", self.qclass, self.qtype, self.qname)
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        try!(self.qname.serialize(cursor));
        try!(cursor.write_u16::<BigEndian>(self.qtype.into()));
        let mut class : u16 = self.qclass.into();
        if self.prefer_unicast { class |= 0x8000u16; }
        try!(cursor.write_u16::<BigEndian>(class));
        Ok(())
    }
    pub fn parse<T>(cursor: &mut Cursor<T>) -> Result<Self, Error> 
        where Cursor<T> : Read
    {
        let n = Name::parse(cursor)?;
        let qtype = cursor.read_u16::<BigEndian>()?;
        let qclass = cursor.read_u16::<BigEndian>()?;
        Ok(Question {
            qname: n,
            prefer_unicast: qclass & (1 << 15) != 0,
            qtype: Type::from(qtype),
            qclass: Class::from(qclass & 0x7fff)
        })
    }

}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

