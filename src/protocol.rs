use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::rc::Rc;
use std::u64;

use bytes::BytesMut;
use futures::sync::mpsc;
use futures::{self, Async, Poll, StartSend, Stream};
use tokio_core::reactor::Handle;
use tokio_io::codec::{Decoder, Encoder, Framed};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_proto::multiplex::{ClientProto, RequestId};

use asnom::common::TagClass;
use asnom::{Consumer, ConsumerState, Input, IResult, Move};
use asnom::structure::{PL, StructureTag};
use asnom::structures::{ASNTag, Integer, Null, Sequence, Tag};
use asnom::parse::parse_uint;
use asnom::parse::Parser;
use asnom::universal::Types;
use asnom::write;

use ldap::LdapOp;

pub struct ProtoBundle {
    pub search_helpers: HashMap<RequestId, SearchHelper>,
    pub id_map: HashSet<LdapRequestId>,
    pub next_id: LdapRequestId,
    pub handle: Handle,
}

impl ProtoBundle {
    fn create_search_helper(&mut self, id: RequestId, tx: mpsc::UnboundedSender<(Tag, Option<StructureTag>)>) {
        self.search_helpers.insert(id, SearchHelper {
            seen: false,
            tx: tx,
        });
    }
}

pub struct SearchHelper {
    seen: bool,
    tx: mpsc::UnboundedSender<(Tag, Option<StructureTag>)>,
}

pub type LdapRequestId = i32;

impl SearchHelper {
    fn send_tag_tuple(&mut self, tuple: (Tag, Option<StructureTag>)) -> io::Result<()> {
        self.tx.send(tuple).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))
    }
}

pub struct LdapCodec {
    bundle: Rc<RefCell<ProtoBundle>>,
}

impl Decoder for LdapCodec {
    type Item = (RequestId, (Tag, Option<StructureTag>));
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let decoding_error = io::Error::new(io::ErrorKind::Other, "decoding error");
        let mut parser = Parser::new();
        let (amt, tag) = match *parser.handle(Input::Element(buf)) {
            ConsumerState::Continue(_) => return Ok(None),
            ConsumerState::Error(_e) => return Err(decoding_error),
            ConsumerState::Done(amt, ref tag) => (amt, tag),
        };
        let amt = match amt {
            Move::Await(_) => return Ok(None),
            Move::Seek(_) => return Err(decoding_error),
            Move::Consume(amt) => amt,
        };
        buf.split_to(amt);
        let tag = tag.clone();
        let mut tags = match tag.match_id(Types::Sequence as u64).and_then(|t| t.expect_constructed()) {
            Some(tags) => tags,
            None => return Err(decoding_error),
        };
        let maybe_controls = tags.pop().expect("element");
        let has_controls = match maybe_controls {
            StructureTag { id, class, ref payload } if class == TagClass::Context && id == 0 => match *payload {
                PL::C(_) => true,
                PL::P(_) => return Err(decoding_error),
            },
            _ => false,
        };
        let (protoop, controls) = if has_controls {
            (tags.pop().expect("element"), Some(maybe_controls))
        } else {
            (maybe_controls, None)
        };
        let id = match parse_uint(tags.pop().expect("element")
                .match_class(TagClass::Universal)
                .and_then(|t| t.match_id(Types::Integer as u64))
                .and_then(|t| t.expect_primitive()).expect("primitive")
                .as_slice()) {
            IResult::Done(_, id) => id,
            _ => return Err(decoding_error),
        };
        match protoop.id {
            4|5|19 => {
                let null_tag = Tag::Null(Null { ..Default::default() });
                let id_tag = Tag::Integer(Integer {
                    inner: id as i64,
                    .. Default::default()
                });
                let mut bundle = self.bundle.borrow_mut();
                let mut helper = match bundle.search_helpers.get_mut(&id) {
                    Some(h) => h,
                    None => return Err(io::Error::new(io::ErrorKind::Other, format!("Id mismatch: {}", id))),
                };
                helper.send_tag_tuple((Tag::StructureTag(protoop), controls))?;
                if helper.seen {
                    Ok(Some((u64::MAX, (null_tag, None))))
                } else {
                    helper.seen = true;
                    Ok(Some((id, (id_tag, None))))
                }
            },
            _ => Ok(Some((id, (Tag::StructureTag(protoop), controls)))),
        }
    }
}

impl Encoder for LdapCodec {
    type Item = (RequestId, LdapOp);
    type Error = io::Error;

    fn encode(&mut self, msg: Self::Item, into: &mut BytesMut) -> io::Result<()> {
        let (id, op) = msg;
        let tag = match op {
            LdapOp::Single(tag) => tag,
            LdapOp::Multi(tag, tx) => {
                self.bundle.borrow_mut().create_search_helper(id, tx);
                tag
            }
            _ => unimplemented!(),
        };
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
        write::encode_into(into, outstruct)?;
        Ok(())
    }
}

pub struct LdapProto {
    bundle: Rc<RefCell<ProtoBundle>>,
}

impl LdapProto {
    pub fn new(handle: Handle) -> LdapProto {
        LdapProto {
            bundle: Rc::new(RefCell::new(ProtoBundle {
                search_helpers: HashMap::new(),
                id_map: HashSet::new(),
                next_id: 1,
                handle: handle,
            }))
        }
    }

    pub fn bundle(&self) -> Rc<RefCell<ProtoBundle>> {
        self.bundle.clone()
    }
}

pub struct ResponseFilter<T> {
    upstream: T,
}

impl<T> Stream for ResponseFilter<T>
    where T: Stream<Item=(RequestId, (Tag, Option<StructureTag>)), Error=io::Error>
{
    type Item = (RequestId, (Tag, Option<StructureTag>));
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            match try_ready!(self.upstream.poll()) {
                Some((id, _)) if id == u64::MAX => continue,
                msg => return Ok(Async::Ready(msg)),
            }
        }
    }
}

impl<T> futures::Sink for ResponseFilter<T>
    where T: futures::Sink<SinkItem=(RequestId, LdapOp), SinkError=io::Error>
{
    type SinkItem = (RequestId, LdapOp);
    type SinkError = io::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.upstream.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.upstream.poll_complete()
    }
}

impl<T: AsyncRead + AsyncWrite + 'static> ClientProto<T> for LdapProto {
    type Request = LdapOp;
    type Response = (Tag, Option<StructureTag>);

    type Transport = ResponseFilter<Framed<T, LdapCodec>>;
    type BindTransport = Result<Self::Transport, io::Error>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        let ldapcodec = LdapCodec {
            bundle: self.bundle.clone(),
        };
        Ok(ResponseFilter {
            upstream: io.framed(ldapcodec),
        })
    }
}
