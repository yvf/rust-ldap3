use std::cell::RefCell;
use std::io;
use std::collections::{HashMap, HashSet};
//use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::u64;

use bytes::BytesMut;
use futures::sync::mpsc;
use futures::{self, task, Async, Future, Poll, StartSend, Stream};
//use futures::sync::oneshot;
use tokio_core::reactor::Handle;
use tokio_io::codec::{Decoder, Encoder, Framed};
use tokio_io::{AsyncRead, AsyncWrite};
//use tokio_proto::streaming::multiplex::{Frame, ClientProto};
use tokio_proto::multiplex::{ClientProto, RequestId};

use asnom::common;
use asnom::Consumer;
use asnom::ConsumerState;
use asnom::Move;
use asnom::Input;
use asnom::IResult;
use asnom::structures::{ASNTag, Integer, Null, Sequence, Tag};
use asnom::parse::Parser;
use asnom::parse::parse_uint;
use asnom::write;

use ldap::LdapOp;

pub struct ProtoBundle {
    pub search_helpers: HashMap<RequestId, SearchHelper>,
    pub id_map: HashSet<LdapRequestId>,
    pub next_id: LdapRequestId,
    pub handle: Handle,
}

impl ProtoBundle {
    fn create_search_helper(&mut self, id: RequestId, tx: mpsc::UnboundedSender<Tag>) {
        self.search_helpers.insert(id, SearchHelper {
            seen: false,
            tx: tx,
        });
    }
}

pub struct SearchHelper {
    seen: bool,
    tx: mpsc::UnboundedSender<Tag>,
}

pub type LdapRequestId = i32;

impl SearchHelper {
    fn send_tag(&mut self, tag: Tag) -> io::Result<()> {
        self.tx.send(tag).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))
    }
}

/*
#[derive(Debug)]
struct StreamExchange {
    data_frames: VecDeque<Tag>,
    waiting_op: Option<oneshot::Sender<Tag>>,
}

#[derive(Debug)]
pub struct Exchanges {
    exchanges: HashMap<u64, StreamExchange>,
}

#[derive(Debug)]
pub enum StreamingResult {
    Entry(Tag),
    Future(oneshot::Receiver<Tag>),
    Error,
}
*/

/*
impl Exchanges {
    fn setup_exchange(&mut self, id: u64) {
        let exchange = StreamExchange {
            data_frames: VecDeque::new(),
            waiting_op: None,
        };
        self.exchanges.insert(id, exchange);
    }

    fn push_frame(&mut self, id: u64, tag: Tag) -> io::Result<()> {
        let exchange = self.exchanges.get_mut(&id).ok_or(io::Error::new(io::ErrorKind::Other, format!("No id {} in exchange", id)))?;
        exchange.data_frames.push_back(tag);
        if let Some(sender) = exchange.waiting_op.take() {
            let tag = exchange.data_frames.pop_front().expect("tag");
            sender.send(tag).map_err(|_| io::Error::new(io::ErrorKind::Other, format!("Couldn't send tag for id {}", id)))?;
        }
        Ok(())
    }

    pub fn pop_frame(&mut self, id: u64) -> StreamingResult {
        let exchange = match self.exchanges.get_mut(&id) {
            Some(exchange) => exchange,
            None => return StreamingResult::Error,
        };
        if exchange.data_frames.is_empty() {
            let (tx, rx) = oneshot::channel::<Tag>();
            exchange.waiting_op = Some(tx);
            StreamingResult::Future(rx)
        } else {
            let tag = exchange.data_frames.pop_front().expect("tag");
            StreamingResult::Entry(tag)
        }
    }
}
*/

//#[derive(Debug)]
pub struct LdapCodec {
    //search_seen: HashSet<u64>,
    bundle: Rc<RefCell<ProtoBundle>>,
}

impl Decoder for LdapCodec {
    //type Item = Frame<Tag, Tag, Self::Error>;
    type Item = (RequestId, Tag);
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
                let null = Tag::Null(Null { ..Default::default() });
                let id_tag = Tag::Integer(Integer {
                    inner: id as i64,
                    .. Default::default()
                });
                return match protoop.id {
                    4 => {
                        let mut bundle = self.bundle.borrow_mut();
                        let mut helper = match bundle.search_helpers.get_mut(&id) {
                            Some(h) => h,
                            None => return Err(io::Error::new(io::ErrorKind::Other, format!("Id mismatch: {}", id))),
                        };
                        helper.send_tag(Tag::StructureTag(protoop))?;
                        if helper.seen {
                            Ok(Some((u64::MAX, null)))
                        } else {
                            helper.seen = true;
                            Ok(Some((id, id_tag)))
                        }
                    },
                    5 => {
                        let mut bundle = self.bundle.borrow_mut();
                        let mut helper = match bundle.search_helpers.get_mut(&id) {
                            Some(h) => h,
                            None => return Err(io::Error::new(io::ErrorKind::Other, format!("Id mismatch: {}", id))),
                        };
                        helper.send_tag(Tag::StructureTag(protoop))?;
                        if helper.seen {
                            Ok(Some((u64::MAX, null)))
                        } else {
                            helper.seen = true;
                            Ok(Some((id, id_tag)))
                        }
                    },
                    _ => {
                        Ok(Some((id, Tag::StructureTag(protoop))))
                    }
                }
                /*
                return match protoop.id {
                    // SearchResultEntry
                    4 => {
                        debug!("Received a search result entry");
                        let is_streaming = self.exchanges.borrow().exchanges.contains_key(&id);
                        let returned_tag = if is_streaming {
                            self.exchanges.borrow_mut().push_frame(id, Tag::StructureTag(protoop))?;
                            null
                        } else {
                            Tag::StructureTag(protoop)
                        };
                        if self.search_seen.contains(&id) {
                            // We have already received the first of those results, so we only send a body frame
                            Ok(Some(Frame::Body {
                                id: id as u64,
                                chunk: Some(returned_tag),
                            }))
                        } else {
                            // If we haven't yet seen that search, we need to initially send a whole message
                            self.search_seen.insert(id);
                            Ok(Some(Frame::Message {
                                id: id as u64,
                                message: returned_tag,
                                body: true,
                                solo: false,
                            }))
                        }
                    },
                    // SearchResultDone
                    5 => {
                        debug!("Received a search result done");
                        let is_streaming = self.exchanges.borrow().exchanges.contains_key(&id);
                        let returned_tag = if is_streaming {
                            self.exchanges.borrow_mut().push_frame(id, Tag::StructureTag(protoop))?;
                            null
                        } else {
                            Tag::StructureTag(protoop)
                        };
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
                                message: returned_tag,
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
                */
            }
        }
        return Err(io::Error::new(io::ErrorKind::Other, "Invalid (RequestId, Tag) received."));
    }
}

impl Encoder for LdapCodec {
    //type Item = Frame<LdapOp, (), Self::Error>;
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
        /*
        if let Frame::Message {message, id, body: _, solo: _} = msg {
            let tag = match message {
                LdapOp::Single(tag) => tag,
                LdapOp::Streaming(tag, sender) => {
                    self.exchanges.borrow_mut().setup_exchange(id);
                    sender.send(id).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
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
        }
        */
        Ok(())
    }
}

pub struct LdapProto {
    //exchanges: Rc<RefCell<Exchanges>>,
    bundle: Rc<RefCell<ProtoBundle>>,
}

impl LdapProto {
    /*
    pub fn new() -> LdapProto {
        LdapProto { exchanges: Rc::new(RefCell::new(Exchanges { exchanges: HashMap::new() })) }
    }
    */
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

    /*
    pub fn exchanges(&self) -> Rc<RefCell<Exchanges>> {
        self.exchanges.clone()
    }
    */
}

pub struct ResponseFilter<T> {
    upstream: T,
}

impl<T> Stream for ResponseFilter<T>
    where T: Stream<Item=(RequestId, Tag), Error=io::Error>
{
    type Item = (RequestId, Tag);
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
    //type RequestBody = ();
    type Response = Tag;
    //type ResponseBody = Tag;
    //type Error = io::Error;

    //type Transport = Framed<T, LdapCodec>;
    type Transport = ResponseFilter<Framed<T, LdapCodec>>;
    type BindTransport = Result<Self::Transport, io::Error>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        let ldapcodec = LdapCodec {
            //search_seen: HashSet::new(),
            bundle: self.bundle.clone(),
        };
        //Ok(io.framed(ldapcodec))
        Ok(ResponseFilter {
            upstream: io.framed(ldapcodec),
        })
    }
}
