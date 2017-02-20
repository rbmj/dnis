use Message;
use Opcode;
use ResponseCode;
use types::*;

use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn parse_example_query() {
    let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                  \x07example\x03com\x00\x00\x01\x00\x01";
    let message = Message::parse(query).unwrap();
    assert_eq!(message.id(), 1573);
    assert!(message.is_request());
    assert!(!message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(!message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    assert_eq!(message.num_answers(), 0);
    assert_eq!(message.num_authority(), 0);
    assert_eq!(message.num_additional(), 0);
    let question = message.get_question(0).unwrap();
    assert_eq!(&question.name().to_string()[..], "example.com");
    assert!(question.is::<A>());
    assert_eq!(question.class(), IN);
}

#[test]
fn parse_example_response() {
    let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                     \x07example\x03com\x00\x00\x01\x00\x01\
                     \xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xf8\
                     \x00\x04]\xb8\xd8\"";
    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 1573);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    assert_eq!(message.num_answers(), 1);
    assert_eq!(message.num_authority(), 0);
    assert_eq!(message.num_additional(), 0);
    let question = message.get_question(0).unwrap();
    assert_eq!(&question.name().to_string()[..], "example.com");
    assert!(question.is::<A>());
    assert_eq!(question.class(), IN);
    let answer = message.get_answer(0).unwrap();
    assert_eq!(&answer.name().to_string()[..], "example.com");
    assert_eq!(answer.class(), IN);
    assert_eq!(answer.ttl, 1272); //TODO
    assert_eq!(*answer.get::<A>().unwrap(), Ipv4Addr::new(93, 184, 216, 34));
}

#[test]
fn parse_response_with_multicast_unique() {
    let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                     \x07example\x03com\x00\x00\x01\x00\x01\
                     \xc0\x0c\x00\x01\x80\x01\x00\x00\x04\xf8\
                     \x00\x04]\xb8\xd8\"";
    let packet = Message::parse(response).unwrap();
    assert_eq!(packet.num_answers(), 1);
    assert_eq!(packet.get_answer(0).unwrap().multicast_unique, true);
    assert_eq!(packet.get_answer(0).unwrap().class(), IN);
}

#[test]
fn parse_ns_response() {
    let response = b"\x4a\xf0\x81\x80\x00\x01\x00\x01\x00\x01\x00\x00\
                     \x03www\x05skype\x03com\x00\x00\x01\x00\x01\
                     \xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\
                     \x00\x1c\x07\x6c\x69\x76\x65\x63\x6d\x73\x0e\x74\
                     \x72\x61\x66\x66\x69\x63\x6d\x61\x6e\x61\x67\x65\
                     \x72\x03\x6e\x65\x74\x00\
                     \xc0\x42\x00\x02\x00\x01\x00\x01\xd5\xd3\x00\x11\
                     \x01\x67\x0c\x67\x74\x6c\x64\x2d\x73\x65\x72\x76\x65\x72\x73\
                     \xc0\x42";
    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 19184);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    let question = message.get_question(0).unwrap();
    assert!(question.is::<A>());
    assert_eq!(question.class(), IN);
    assert_eq!(&question.name().to_string()[..], "www.skype.com");
    assert_eq!(message.num_answers(), 1);
    let answer = message.get_answer(0).unwrap();
    assert_eq!(answer.class(), IN);
    assert_eq!(answer.ttl, 3600);
    assert_eq!(&answer.get::<CNAME>().unwrap().to_string()[..], "livecms.trafficmanager.net");
    assert_eq!(message.num_authority(), 1);
    let authority = message.get_authority(0).unwrap();
    assert_eq!(&authority.name().to_string()[..], "net");
    assert_eq!(authority.class(), IN);
    assert_eq!(authority.ttl, 120275);
    assert_eq!(&authority.get::<NS>().unwrap().to_string()[..], "g.gtld-servers.net");
}

#[test]
fn parse_soa_response() {
    let response = b"\x9f\xc5\x85\x83\x00\x01\x00\x00\x00\x01\x00\x00\
                     \x0edlkfjkdjdslfkj\x07youtube\x03com\x00\x00\x01\x00\x01\
                     \xc0\x1b\x00\x06\x00\x01\x00\x00\x2a\x30\x00\x1e\xc0\x1b\
                     \x05admin\xc0\x1b\x77\xed\x2a\x73\x00\x00\x51\x80\x00\x00\
                     \x0e\x10\x00\x00\x3a\x80\x00\x00\x2a\x30";
    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 40901);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NxDomain);
    assert_eq!(message.num_questions(), 1);
    let question = message.get_question(0).unwrap();
    assert_eq!(question.class(), IN);
    assert!(question.is::<A>());
    assert_eq!(&question.name().to_string()[..], "dlkfjkdjdslfkj.youtube.com");
    assert_eq!(message.num_answers(), 0);
    assert_eq!(message.num_authority(), 1);
    let authority = message.get_authority(0).unwrap();
    assert_eq!(authority.class(), IN);
    assert_eq!(authority.ttl, 10800);
    let soa = authority.get::<SOA>().unwrap();
    assert_eq!(&soa.primary_ns.to_string()[..], "youtube.com");
    assert_eq!(&soa.mailbox.to_string()[..], "admin.youtube.com");
    assert_eq!(soa.serial, 2012031603);
    assert_eq!(soa.refresh, 20864);
    assert_eq!(soa.retry, 3600);
    assert_eq!(soa.expire, 14976);
    assert_eq!(soa.min_ttl, 10800);
}
 
#[test]
fn parse_ptr_response() {
    let response = b"\x53\xd6\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                     \x0269\x0293\x0275\x0272\x07in-addr\x04arpa\x00\
                     \x00\x0c\x00\x01\
                     \xc0\x0c\x00\x0c\x00\x01\x00\x01\x51\x80\x00\x1e\
                     \x10pool-72-75-93-69\x07verizon\x03net\x00";
    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 21462);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    let question = message.get_question(0).unwrap();
    assert_eq!(question.class(), IN);
    assert!(question.is::<PTR>());
    assert_eq!(&question.name().to_string()[..], "69.93.75.72.in-addr.arpa");
    assert_eq!(message.num_answers(), 1);
    let answer = message.get_answer(0).unwrap();
    assert_eq!(&answer.name().to_string()[..], "69.93.75.72.in-addr.arpa");
    assert_eq!(answer.class(), IN);
    assert_eq!(answer.ttl, 86400);
    assert_eq!(&answer.get::<PTR>().unwrap().to_string()[..], "pool-72-75-93-69.verizon.net");
    assert_eq!(message.num_authority(), 0);
    assert_eq!(message.num_additional(), 0);
}

#[test]
fn parse_additional_record_response() {
    let response = b"\x4a\xf0\x81\x80\x00\x01\x00\x01\x00\x01\x00\x01\
                     \x03www\x05skype\x03com\x00\x00\x01\x00\x01\
                     \xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\
                     \x00\x1c\x07\x6c\x69\x76\x65\x63\x6d\x73\x0e\x74\
                     \x72\x61\x66\x66\x69\x63\x6d\x61\x6e\x61\x67\x65\
                     \x72\x03\x6e\x65\x74\x00\
                     \xc0\x42\x00\x02\x00\x01\x00\x01\xd5\xd3\x00\x11\
                     \x01\x67\x0c\x67\x74\x6c\x64\x2d\x73\x65\x72\x76\x65\x72\x73\
                     \xc0\x42\
                     \x01\x61\xc0\x55\x00\x01\x00\x01\x00\x00\xa3\x1c\
                     \x00\x04\xc0\x05\x06\x1e";
    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 19184);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    let question = message.get_question(0).unwrap();
    assert!(question.is::<A>());
    assert_eq!(question.class(), IN);
    assert_eq!(&question.name().to_string()[..], "www.skype.com");
    assert_eq!(message.num_answers(), 1);
    let answer = message.get_answer(0).unwrap();
    assert_eq!(&answer.name().to_string()[..], "www.skype.com");
    assert_eq!(answer.class(), IN);
    assert_eq!(answer.ttl, 3600);
    assert_eq!(&answer.get::<CNAME>().unwrap().to_string()[..], "livecms.trafficmanager.net");
    assert_eq!(message.num_authority(), 1);
    let authority = message.get_authority(0).unwrap();
    assert_eq!(&authority.name().to_string()[..], "net");
    assert_eq!(authority.class(), IN);
    assert_eq!(authority.ttl, 120275);
    assert_eq!(&authority.get::<NS>().unwrap().to_string()[..], "g.gtld-servers.net");
    assert_eq!(message.num_additional(), 1);
    let additional = message.get_additional(0).unwrap();
    assert_eq!(&additional.name().to_string()[..], "a.gtld-servers.net");
    assert_eq!(additional.class(), IN);
    assert_eq!(additional.ttl, 41756);
    assert_eq!(*additional.get::<A>().unwrap(), Ipv4Addr::new(192, 5, 6, 30));
}

#[test]
fn parse_multiple_answers() {
    let response = b"\x9d\xe9\x81\x80\x00\x01\x00\x06\x00\x00\x00\x00\
        \x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\
        \x00\x01\x00\x01\x00\x00\x00\xef\x00\x04@\xe9\
        \xa4d\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\
        \x00\x04@\xe9\xa4\x8b\xc0\x0c\x00\x01\x00\x01\
        \x00\x00\x00\xef\x00\x04@\xe9\xa4q\xc0\x0c\x00\
        \x01\x00\x01\x00\x00\x00\xef\x00\x04@\xe9\xa4f\
        \xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\x00\x04@\
        \xe9\xa4e\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\
        \x00\x04@\xe9\xa4\x8a";
    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 40425);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    let question = message.get_question(0).unwrap();
    assert!(question.is::<A>());
    assert_eq!(question.class(), IN);
    assert_eq!(&question.name().to_string()[..], "google.com");
    assert_eq!(message.num_answers(), 6);
    let ips = vec![
        Ipv4Addr::new(64, 233, 164, 100),
        Ipv4Addr::new(64, 233, 164, 139),
        Ipv4Addr::new(64, 233, 164, 113),
        Ipv4Addr::new(64, 233, 164, 102),
        Ipv4Addr::new(64, 233, 164, 101),
        Ipv4Addr::new(64, 233, 164, 138),
    ];
    for i in 0..6 {
        let answer = message.get_answer(i).unwrap();
        assert_eq!(&answer.name().to_string()[..], "google.com");
        assert_eq!(answer.class(), IN);
        assert_eq!(answer.ttl, 239);
        assert_eq!(*answer.get::<A>().unwrap(), ips[i]);
    }
}

#[test]
fn parse_srv_query() {
    let query = b"[\xd9\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
        \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01";
    let message = Message::parse(query).unwrap();
    assert_eq!(message.id(), 23513);
    assert!(message.is_request());
    assert!(!message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(!message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    assert_eq!(message.num_answers(), 0);
    assert_eq!(message.num_authority(), 0);
    assert_eq!(message.num_additional(), 0);
    let question = message.get_question(0).unwrap();
    assert_eq!(&question.name().to_string()[..], "_xmpp-server._tcp.gmail.com");
    assert!(question.is::<SRV>());
    assert_eq!(question.class(), IN);
}

#[test]
fn parse_multicast_prefer_unicast_query() {
    let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                  \x07example\x03com\x00\x00\x01\x80\x01";
    let packet = Message::parse(query).unwrap();
    assert_eq!(packet.num_questions(), 1);
    assert!(packet.get_question(0).unwrap().is::<A>());
    assert_eq!(packet.get_question(0).unwrap().class(), IN);
    assert_eq!(packet.get_question(0).unwrap().prefer_unicast, true);
}

#[test]
fn parse_srv_response() {
    let response = b"[\xd9\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\
        \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01\
        \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00 \x00\x05\x00\x00\
        \x14\x95\x0bxmpp-server\x01l\x06google\x03com\x00\xc0\x0c\x00!\
        \x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\x14\x95\
        \x04alt3\x0bxmpp-server\x01l\x06google\x03com\x00\
        \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
        \x14\x95\x04alt1\x0bxmpp-server\x01l\x06google\x03com\x00\
        \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
        \x14\x95\x04alt2\x0bxmpp-server\x01l\x06google\x03com\x00\
        \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
        \x14\x95\x04alt4\x0bxmpp-server\x01l\x06google\x03com\x00";
    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 23513);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    let question = message.get_question(0).unwrap();
    assert!(question.is::<SRV>());
    assert_eq!(question.class(), IN);
    assert_eq!(&question.name().to_string()[..], "_xmpp-server._tcp.gmail.com");
    assert_eq!(message.num_answers(), 5);
    let items = vec![
        (5, 0, 5269, "xmpp-server.l.google.com"),
        (20, 0, 5269, "alt3.xmpp-server.l.google.com"),
        (20, 0, 5269, "alt1.xmpp-server.l.google.com"),
        (20, 0, 5269, "alt2.xmpp-server.l.google.com"),
        (20, 0, 5269, "alt4.xmpp-server.l.google.com"),
    ];
    for i in 0..5 {
        let answer = message.get_answer(i).unwrap();
        assert_eq!(&answer.name().to_string()[..], "_xmpp-server._tcp.gmail.com");
        assert_eq!(answer.class(), IN);
        assert_eq!(answer.ttl, 900);
        let srv = answer.get::<SRV>().unwrap();
        assert_eq!(srv.priority, items[i].0);
        assert_eq!(srv.weight, items[i].1);
        assert_eq!(srv.port, items[i].2);
        assert_eq!(&srv.target.to_string()[..], items[i].3);
    }
}

#[test]
fn parse_mx_response() {
    let response = b"\xe3\xe8\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\
        \x05gmail\x03com\x00\x00\x0f\x00\x01\xc0\x0c\x00\x0f\x00\x01\
        \x00\x00\x04|\x00\x1b\x00\x05\rgmail-smtp-in\x01l\x06google\xc0\
        \x12\xc0\x0c\x00\x0f\x00\x01\x00\x00\x04|\x00\t\x00\
        \n\x04alt1\xc0)\xc0\x0c\x00\x0f\x00\x01\x00\x00\x04|\
        \x00\t\x00(\x04alt4\xc0)\xc0\x0c\x00\x0f\x00\x01\x00\
        \x00\x04|\x00\t\x00\x14\x04alt2\xc0)\xc0\x0c\x00\x0f\
        \x00\x01\x00\x00\x04|\x00\t\x00\x1e\x04alt3\xc0)";
    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 58344);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    let question = message.get_question(0).unwrap();
    assert!(question.is::<MX>());
    assert_eq!(question.class(), IN);
    assert_eq!(&question.name().to_string()[..], "gmail.com");
    assert_eq!(message.num_answers(), 5);
    let items = vec![
        ( 5, "gmail-smtp-in.l.google.com"),
        (10, "alt1.gmail-smtp-in.l.google.com"),
        (40, "alt4.gmail-smtp-in.l.google.com"),
        (20, "alt2.gmail-smtp-in.l.google.com"),
        (30, "alt3.gmail-smtp-in.l.google.com"),
    ];
    for i in 0..5 {
        let answer = message.get_answer(i).unwrap();
        assert_eq!(&answer.name().to_string()[..], "gmail.com");
        assert_eq!(answer.class(), IN);
        assert_eq!(answer.ttl, 1148);
        let mx = answer.get::<MX>().unwrap();
        assert_eq!(mx.preference, items[i].0);
        assert_eq!(&mx.exchange.to_string()[..], items[i].1);
    }
}

#[test]
fn parse_aaaa_response() {
    let response = b"\xa9\xd9\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06\
        google\x03com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\
        \x00\x8b\x00\x10*\x00\x14P@\t\x08\x12\x00\x00\x00\x00\x00\x00 \x0e";
    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 43481);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    assert_eq!(message.num_answers(), 1);
    assert_eq!(message.num_authority(), 0);
    assert_eq!(message.num_additional(), 0);
    let question = message.get_question(0).unwrap();
    assert_eq!(&question.name().to_string()[..], "google.com");
    assert!(question.is::<AAAA>());
    assert_eq!(question.class(), IN);
    let answer = message.get_answer(0).unwrap();
    assert_eq!(&answer.name().to_string()[..], "google.com");
    assert_eq!(answer.class(), IN);
    assert_eq!(answer.ttl, 139); //TODO
    assert_eq!(*answer.get::<AAAA>().unwrap(),
        Ipv6Addr::new(0x2a00, 0x1450, 0x4009, 0x0812, 0, 0, 0, 0x200e));
}

#[test]
fn parse_cname_response() {
    let response = b"\xfc\x9d\x81\x80\x00\x01\x00\x06\x00\x02\x00\x02\x03\
        cdn\x07sstatic\x03net\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\
        \x00\x00\x00f\x00\x02\xc0\x10\xc0\x10\x00\x01\x00\x01\x00\x00\x00\
        f\x00\x04h\x10g\xcc\xc0\x10\x00\x01\x00\x01\x00\x00\x00f\x00\x04h\
        \x10k\xcc\xc0\x10\x00\x01\x00\x01\x00\x00\x00f\x00\x04h\x10h\xcc\
        \xc0\x10\x00\x01\x00\x01\x00\x00\x00f\x00\x04h\x10j\xcc\xc0\x10\
        \x00\x01\x00\x01\x00\x00\x00f\x00\x04h\x10i\xcc\xc0\x10\x00\x02\
        \x00\x01\x00\x00\x99L\x00\x0b\x08cf-dns02\xc0\x10\xc0\x10\x00\x02\
        \x00\x01\x00\x00\x99L\x00\x0b\x08cf-dns01\xc0\x10\xc0\xa2\x00\x01\
        \x00\x01\x00\x00\x99L\x00\x04\xad\xf5:5\xc0\x8b\x00\x01\x00\x01\x00\
        \x00\x99L\x00\x04\xad\xf5;\x04";

    let message = Message::parse(response).unwrap();
    assert_eq!(message.id(), 64669);
    assert!(!message.is_request());
    assert!(message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    let question = message.get_question(0).unwrap();
    assert!(question.is::<A>());
    assert_eq!(question.class(), IN);
    assert_eq!(&question.name().to_string()[..], "cdn.sstatic.net");
    assert_eq!(message.num_answers(), 6);
    let answer = message.get_answer(0).unwrap();
    assert_eq!(&answer.name().to_string()[..], "cdn.sstatic.net");
    assert_eq!(answer.class(), IN);
    assert_eq!(answer.ttl, 102);
    assert_eq!(&answer.get::<CNAME>().unwrap().to_string()[..], "sstatic.net");
    let ips = vec![
        Ipv4Addr::new(104, 16, 103, 204),
        Ipv4Addr::new(104, 16, 107, 204),
        Ipv4Addr::new(104, 16, 104, 204),
        Ipv4Addr::new(104, 16, 106, 204),
        Ipv4Addr::new(104, 16, 105, 204),
    ];
    for i in 1..6 {
        let answer = message.get_answer(i).unwrap();
        assert_eq!(&answer.name().to_string()[..], "sstatic.net");
        assert_eq!(answer.class(), IN);
        assert_eq!(answer.ttl, 102);
        assert_eq!(*answer.get::<A>().unwrap(), ips[i-1]);
    }
    assert_eq!(message.num_authority(), 2);
    assert_eq!(message.num_additional(), 2);
}

#[test]
fn parse_example_query_edns() {
    let query = b"\x95\xce\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\
        \x06google\x03com\x00\x00\x01\x00\
        \x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00";
    let message = Message::parse(query).unwrap();
    assert_eq!(message.id(), 38350);
    assert!(message.is_request());
    assert!(!message.is_response());
    assert_eq!(message.opcode(), Opcode::StandardQuery);
    assert!(!message.is_authoritative());
    assert!(!message.is_truncated());
    assert!(message.recursion_desired());
    assert!(!message.recursion_available());
    assert_eq!(message.response_code(), ResponseCode::NoError);
    assert_eq!(message.num_questions(), 1);
    let question = message.get_question(0).unwrap();
    assert!(question.is::<A>());
    assert_eq!(question.class(), IN);
    assert_eq!(&question.name().to_string()[..], "google.com");
    assert_eq!(message.num_answers(), 0);
    let opt = message.opt.as_ref().unwrap();
    assert_eq!(opt.udp, 4096);
    assert_eq!(opt.extrcode, 0);
    assert_eq!(opt.version, 0);
    assert_eq!(opt.flags, 0);
}
