use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::convert::AsRef;
use std::io;
use std::rc::Rc;

use asnom::structure::StructureTag;
use asnom::structures::{Boolean, Enumerated, Integer, OctetString, Sequence, Tag};
use asnom::common::TagClass::*;

use futures::{Async, Future, Poll, Stream};
use futures::sync::{mpsc, oneshot};
use tokio_proto::multiplex::RequestId;
use tokio_service::Service;

use controls::Control;
use filter::parse;
use ldap::{bundle, next_search_options, next_req_controls};
use ldap::{Ldap, LdapOp};
use protocol::{LdapResult, ProtoBundle};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Scope {
    Base     = 0,
    OneLevel = 1,
    Subtree  = 2,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DerefAliases {
    Never     = 0,
    Searching = 1,
    Finding   = 2,
    Always    = 3,
}

pub enum SearchItem {
    Entry(StructureTag),
    Referral(StructureTag),
    Done(RequestId, LdapResult, Vec<Control>),
}

pub struct SearchStream {
    id: RequestId,
    bundle: Rc<RefCell<ProtoBundle>>,
    _tx_i: mpsc::UnboundedSender<SearchItem>,
    rx_i: mpsc::UnboundedReceiver<SearchItem>,
    tx_r: Option<oneshot::Sender<(LdapResult, Vec<Control>)>>,
    refs: Vec<HashSet<String>>,
}

impl Stream for SearchStream {
    type Item = StructureTag;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            let item = try_ready!(self.rx_i.poll().map_err(|_e| io::Error::new(io::ErrorKind::Other, "poll search stream")));
            match item {
                Some(SearchItem::Done(_id, mut result, controls)) => {
                    result.refs.extend(self.refs.drain(..));
                    let mut bundle = self.bundle.borrow_mut();
                    let msgid = match bundle.search_helpers.get(&self.id) {
                        Some(ref helper) => helper.msgid,
                        None => return Ok(Async::Ready(None)),
                    };
                    bundle.search_helpers.remove(&self.id);
                    bundle.id_map.remove(&msgid);
                    let tx_r = self.tx_r.take().expect("oneshot tx");
                    tx_r.send((result, controls)).map_err(|_e| io::Error::new(io::ErrorKind::Other, "send result"))?;
                    return Ok(Async::Ready(None));
                },
                Some(SearchItem::Entry(tag)) => return Ok(Async::Ready(Some(tag))),
                Some(SearchItem::Referral(tag)) => {
                    self.refs.push(tag.expect_constructed().expect("referrals").into_iter()
                        .map(|t| t.expect_primitive().expect("octet string"))
                        .map(String::from_utf8)
                        .map(|s| s.expect("uri"))
                        .collect());
                    continue;
                },
                None => return Ok(Async::Ready(None)),
            }
        }
    }
}

#[derive(Debug)]
pub struct SearchEntry {
    pub dn: String,
    pub attrs: HashMap<String, Vec<String>>,
}

impl SearchEntry {
    pub fn construct(tag: StructureTag) -> SearchEntry {
        let mut tags = tag.match_id(4).and_then(|t| t.expect_constructed()).expect("entry").into_iter();
        let dn = String::from_utf8(tags.next().expect("element").expect_primitive().expect("octet string"))
            .expect("dn");
        let mut attr_vals = HashMap::new();
        let attrs = tags.next().expect("element").expect_constructed().expect("attrs").into_iter();
        for a_v in attrs {
            let mut part_attr = a_v.expect_constructed().expect("partial attribute").into_iter();
            let a_type = String::from_utf8(part_attr.next().expect("element").expect_primitive().expect("octet string"))
                .expect("attribute type");
            let values = part_attr.next().expect("element").expect_constructed().expect("values").into_iter()
                .map(|t| t.expect_primitive().expect("octet string"))
                .map(String::from_utf8)
                .map(|s| s.expect("value"))
                .collect();
            attr_vals.insert(a_type, values);
        }
        SearchEntry {
            dn: dn,
            attrs: attr_vals,
        }
    }
}

pub struct SearchOptions {
    deref: DerefAliases,
    typesonly: bool,
    timelimit: i32,
    sizelimit: i32,
}

impl SearchOptions {
    pub fn new() -> Self {
        SearchOptions {
            deref: DerefAliases::Never,
            typesonly: false,
            timelimit: 0,
            sizelimit: 0,
        }
    }

    pub fn deref(mut self, d: DerefAliases) -> Self {
        self.deref = d;
        self
    }

    pub fn typesonly(mut self, typesonly: bool) -> Self {
        self.typesonly = typesonly;
        self
    }

    pub fn timelimit(mut self, timelimit: i32) -> Self {
        self.timelimit = timelimit;
        self
    }

    pub fn sizelimit(mut self, sizelimit: i32) -> Self {
        self.sizelimit = sizelimit;
        self
    }
}

impl Ldap {
    pub fn search<S: AsRef<str>>(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<S>) ->
            Box<Future<Item=(SearchStream, oneshot::Receiver<(LdapResult, Vec<Control>)>), Error=io::Error>> {
        let opts = match next_search_options(self) {
            Some(opts) => opts,
            None => SearchOptions::new(),
        };
        let req = Tag::Sequence(Sequence {
            id: 3,
            class: Application,
            inner: vec![
                   Tag::OctetString(OctetString {
                       inner: Vec::from(base.as_bytes()),
                       .. Default::default()
                   }),
                   Tag::Enumerated(Enumerated {
                       inner: scope as i64,
                       .. Default::default()
                   }),
                   Tag::Enumerated(Enumerated {
                       inner: opts.deref as i64,
                       .. Default::default()
                   }),
                   Tag::Integer(Integer {
                       inner: opts.sizelimit as i64,
                       .. Default::default()
                   }),
                   Tag::Integer(Integer {
                       inner: opts.timelimit as i64,
                       .. Default::default()
                   }),
                   Tag::Boolean(Boolean {
                       inner: opts.typesonly,
                       .. Default::default()
                   }),
                   parse(filter).unwrap(),
                   Tag::Sequence(Sequence {
                       inner: attrs.into_iter().map(|s|
                            Tag::OctetString(OctetString { inner: Vec::from(s.as_ref()), ..Default::default() })).collect(),
                       .. Default::default()
                   })
            ],
        });

        let (tx_i, rx_i) = mpsc::unbounded::<SearchItem>();
        let (tx_r, rx_r) = oneshot::channel::<(LdapResult, Vec<Control>)>();
        let bundle = bundle(self);
        let fut = self.call(LdapOp::Multi(req, tx_i.clone(), next_req_controls(self))).and_then(move |res| {
            let id = match res {
                (Tag::Integer(Integer { id: _, class: _, inner }), _) => inner,
                _ => unimplemented!(),
            };
            Ok((SearchStream {
                id: id as RequestId,
                bundle: bundle,
                _tx_i: tx_i,
                rx_i: rx_i,
                tx_r: Some(tx_r),
                refs: Vec::new(),
            }, rx_r))
        });

        Box::new(fut)
    }
}
