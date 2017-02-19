use std::fmt;
use std::str::FromStr;
use std::io::{Cursor, Write, Read};
use std::collections::VecDeque;
use std::collections::vec_deque::Iter as VecDequeIter;
use byteorder::{WriteBytesExt, ReadBytesExt};
use itertools::Itertools;
use dns_parser::Error::LabelIsNotAscii;

use super::Error;

#[derive(Clone)]
pub struct Label {
    data: String
}

impl Label {
    fn check(s: &str) -> Result<(), Error> {
        if !s.chars().all(|c| c.is_digit(36) || c == '-') || s.len() == 0 {
            return Err(Error::ParserError(LabelIsNotAscii));
        }
        Ok(())
    }
    pub fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_string(s.to_string())
    }
    pub fn from_string(s: String) -> Result<Self, Error> {
        try!(Self::check(s.as_str()));
        Ok(Label { data: s })
    }
    pub fn as_str(&self) -> &str {
        self.data.as_str()
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        cursor.write_u8(self.data.len() as u8)?;
        if let Err(e) = cursor.write_all(self.as_str().as_bytes()) {
            return Err(Error::IOError(e));
        }
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.data.fmt(f)
    }
}

#[derive(Clone)]
pub struct Name {
    labels: VecDeque<Label>
}

enum ParseLabel {
    L(Label),
    End,
    Pointer(u16)
}

impl Name {
    pub fn from_string(s: String) -> Result<Self, Error> {
        Self::from_str(s.as_str())
    }
    pub fn to_string(&self) -> String {
        self.iter().join(".")
    }
    pub fn push(&mut self, l: Label) {
        self.labels.push_front(l);
    }
    pub fn pop(&mut self) {
        self.labels.pop_front();
    }
    pub fn iter(&self) -> VecDequeIter<Label> {
        self.labels.iter()
    }
    pub fn len(&self) -> usize {
        self.labels.iter().map(|l| l.len()).fold(0, |acc, x| acc + x)
    }
    fn read_label<T>(cursor: &mut Cursor<T>, buf: &mut [u8]) -> Result<ParseLabel, Error>
        where Cursor<T> : Read
    {
        let len = cursor.read_u8()?;
        if len == 0 { return Ok(ParseLabel::End); }
        if len >> 6 == 0b11 {
            let mut dest = (len & 0b0011_1111) as u16;
            dest = (dest << 8) | (cursor.read_u8()? as u16);
            return Ok(ParseLabel::Pointer(dest));
        }
        if len >> 6 == 0b00 {
            cursor.read_exact(&mut buf[0..(len as usize)])?;
            let label = Label::from_str(&*String::from_utf8_lossy(&buf[0..(len as usize)]))?;
            return Ok(ParseLabel::L(label));
        }
        return Err(Error::UnknownLabelFormat);
    }
    pub fn parse<T>(cursor: &mut Cursor<T>) -> Result<Name, Error>
        where Cursor<T> : Read
    {
        let mut name = Name { labels: VecDeque::new() };
        let mut pos = 0u64; //always invalid
        let mut buf = [0u8; 64];
        for _ in 1..128 { //prevent malicious packets from causing infinite loop
            match Self::read_label(cursor, &mut buf)? {
                ParseLabel::End => {
                    if name.len() > 255 {
                        return Err(Error::NameTooLong);
                    }
                    if pos != 0 {
                        cursor.set_position(pos);
                    }
                    return Ok(name);
                }
                ParseLabel::L(l) => {
                    name.labels.push_back(l);
                }
                ParseLabel::Pointer(off) => {
                    if pos == 0 {
                        pos = cursor.position();
                    }
                    cursor.set_position(off as u64);
                }
            }
        }
        //maximum label depth exceeded
        return Err(Error::NameTooLong);
    }
    pub fn serialize<T>(&self, cursor: &mut Cursor<T>) -> Result<(), Error> 
        where Cursor<T> : Write
    {
        for l in self.iter() {
            try!(l.serialize(cursor));
        }
        try!(cursor.write_u8(0));
        Ok(())
    }
}

impl FromStr for Name {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(Name { labels: s.split('.').rev().map(|s| Label::from_str(s))
            .collect::<Result<VecDeque<_>, Error>>()? })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}

