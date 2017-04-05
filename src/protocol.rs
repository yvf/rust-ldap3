use std::io;
use std::collections::HashSet;

use bytes::BytesMut;
use tokio_io::codec::{Decoder, Encoder, Framed};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_proto::streaming::multiplex::{Frame, ClientProto};

use asnom::common;
use asnom::Consumer;
use asnom::ConsumerState;
use asnom::Move;
use asnom::Input;
use asnom::IResult;
use asnom::structures::{Tag, Integer, Sequence, ASNTag};
use asnom::parse::Parser;
use asnom::parse::parse_uint;
use asnom::write;

use ldap::LdapOp;

#[derive(Debug, Clone)]
pub struct LdapCodec {
    search_seen: HashSet<u64>,
}

impl Decoder for LdapCodec {
    type Item = Frame<Tag, Tag, Self::Error>;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut parser = Parser::new();
        let (amt, tag) = match *parser.handle(Input::Element(buf)) {
            ConsumerState::Continue(_) => return Ok(None),
            ConsumerState::Error(_e) => return Err(io::Error::from(io::ErrorKind::Other)),
            ConsumerState::Done(amt, ref tag) => (amt, tag),
        };
        let amt = match amt {
            Move::Await(_) => return Ok(None),
            Move::Seek(_) => return Err(io::Error::from(io::ErrorKind::Other)),
            Move::Consume(amt) => amt,
        };
        buf.split_to(amt);
        let tag = tag.clone();
        if let Some(mut tags) = tag.match_id(16u64).and_then(|x| x.expect_constructed()) {
            let protoop = tags.pop().unwrap();
            let msgid: Vec<u8> = tags.pop().unwrap()
                            .match_class(common::TagClass::Universal)
                            .and_then(|x| x.match_id(2u64))
                            .and_then(|x| x.expect_primitive()).unwrap();
            if let IResult::Done(_, id) = parse_uint(msgid.as_slice()) {
                return match protoop.id {
                    // SearchResultEntry
                    4 => {
                        debug!("Received a search result entry");
                        // We have already received the first of those results, so we only
                        // send a body frame.
                        if self.search_seen.contains(&id) {
                            Ok(Some(Frame::Body {
                                id: id as u64,
                                chunk: Some(Tag::StructureTag(protoop)),
                            }))
                        } // If we haven't yet seen that search, we need to initially send a whole message
                        else {
                            self.search_seen.insert(id);
                            Ok(Some(Frame::Message {
                                id: id as u64,
                                message: Tag::StructureTag(protoop),
                                body: true,
                                solo: false,
                            }))
                        }
                    },
                    // SearchResultDone
                    5 => {
                        debug!("Received a search result done");
                        let seen_res_entry = self.search_seen.contains(&id);
                        self.search_seen.remove(&id);
                        if seen_res_entry {
                            Ok(Some(Frame::Body {
                                id: id as u64,
                                chunk: None,
                            }))
                        } else {
                            Ok(Some(Frame::Message {
                                id: id as u64,
                                message: Tag::StructureTag(protoop),
                                body: false,
                                solo: false,
                            }))
                        }
                    },
                    // Any other Message
                    _ => {
                        debug!("Received a tag id {}", id);
                        Ok(Some(Frame::Message {
                            id: id as u64,
                            message: Tag::StructureTag(protoop),
                            body: false,
                            solo: false,
                        }))
                    },
                }
            }
        }
        return Err(io::Error::new(io::ErrorKind::Other, "Invalid (RequestId, Tag) received."));
    }
}

impl Encoder for LdapCodec {
    type Item = Frame<LdapOp, (), Self::Error>;
    type Error = io::Error;

    fn encode(&mut self, msg: Self::Item, into: &mut BytesMut) -> io::Result<()> {
        if let Frame::Message {message, id, body: _, solo: _} = msg {
            match message {
                LdapOp::Single(tag) => {
                    let outtag = Tag::Sequence(Sequence {
                        inner: vec![
                            Tag::Integer(Integer {
                                inner: id as i64,
                                .. Default::default()
                            }),
                            tag,
                        ],
                        .. Default::default()
                    });

                    let outstruct = outtag.into_structure();
                    trace!("Sending packet: {:?}", &outstruct);
                    try!(write::encode_into(into, outstruct));
                }
                _ => unimplemented!(),
            }
        }
        Ok(())
    }
}

pub struct LdapProto;

impl<T: AsyncRead + AsyncWrite + 'static> ClientProto<T> for LdapProto {
    type Request = LdapOp;
    type RequestBody = ();
    type Response = Tag;
    type ResponseBody = Tag;
    type Error = io::Error;

    type Transport = Framed<T, LdapCodec>;
    type BindTransport = Result<Self::Transport, io::Error>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        let ldapcodec = LdapCodec { search_seen: HashSet::new() };
        Ok(io.framed(ldapcodec))
    }
}
