use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io;
use std::rc::Rc;

use asnom::structure::StructureTag;
use asnom::structures::{Tag, Sequence, Integer, OctetString, Boolean};
use asnom::common::TagClass::*;

use filter::parse;

use futures::{Async, Future, Poll, Stream};
use futures::sync::mpsc;
use tokio_proto::multiplex::RequestId;
use tokio_service::Service;

use ldap::bundle;
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
    Never             = 0,
    InSearch          = 1,
    FindingBaseObject = 2,
    Always            = 3,
}

pub enum SearchItem {
    Entry(StructureTag),
    Referral(StructureTag),
    Done(RequestId, LdapResult, Option<StructureTag>),
}

pub struct SearchStream {
    id: RequestId,
    bundle: Rc<RefCell<ProtoBundle>>,
    rx: mpsc::UnboundedReceiver<SearchItem>,
    refs: Vec<HashSet<String>>,
}

impl Stream for SearchStream {
    type Item = Tag;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            let item = try_ready!(self.rx.poll().map_err(|_e| io::Error::new(io::ErrorKind::Other, "")));
            match item {
                Some(SearchItem::Done(_id, mut _result, _controls)) => {
                    _result.refs.extend(self.refs.drain(..));
                    let mut bundle = self.bundle.borrow_mut();
                    let msgid = match bundle.search_helpers.get(&self.id) {
                        Some(ref helper) => helper.msgid,
                        None => return Ok(Async::Ready(None)),
                    };
                    bundle.search_helpers.remove(&self.id);
                    bundle.id_map.remove(&msgid);
                    return Ok(Async::Ready(None));
                },
                Some(SearchItem::Entry(tag)) => return Ok(Async::Ready(Some(Tag::StructureTag(tag)))),
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

#[derive(Clone, Debug, PartialEq)]
pub enum SearchEntry {
    Reference(Vec<String>),
    Object {
        object_name: String,
        attributes: HashMap<String, Vec<String>>,
    },
}

impl SearchEntry {
    pub fn construct(tag: Tag) -> SearchEntry {
        match tag {
            Tag::StructureTag(t) => {
                match t.id {
                    // Search Result Entry
                    // Search Result Done (if the result set is empty)
                    4|5 => {
                        let mut tags = t.expect_constructed().unwrap();
                        let attributes = tags.pop().unwrap();
                        let object_name = tags.pop().unwrap();
                        let object_name = String::from_utf8(object_name.expect_primitive().unwrap()).unwrap();

                        let a = construct_attributes(attributes.expect_constructed().unwrap_or(vec![])).unwrap();

                        SearchEntry::Object {
                            object_name: object_name,
                            attributes: a,
                        }
                    },
                    // Search Result Reference
                    19 => {
                        // TODO actually handle this case
                        SearchEntry::Reference(vec![])
                    },
                    _ => panic!("Search received a non-search tag!"),
                }
            }
            _ => unimplemented!()
        }
    }
}

fn construct_attributes(tags: Vec<StructureTag>) -> Option<HashMap<String, Vec<String>>> {
    let mut map = HashMap::new();
    for tag in tags.into_iter() {
        let mut inner = tag.expect_constructed().unwrap();

        let values = inner.pop().unwrap();
        let valuev = values.expect_constructed().unwrap()
                           .into_iter()
                           .map(|t| t.expect_primitive().unwrap())
                           .map(|v| String::from_utf8(v).unwrap())
                           .collect();
        let key = inner.pop().unwrap();
        let keystr = String::from_utf8(key.expect_primitive().unwrap()).unwrap();

        map.insert(keystr, valuev);
    }

    Some(map)
}

impl Ldap {
    pub fn search(&self,
                    base: String,
                    scope: Scope,
                    deref: DerefAliases,
                    typesonly: bool,
                    filter: String,
                    attrs: Vec<String>) ->
        Box<Future<Item=SearchStream, Error=io::Error>> {
        let req = Tag::Sequence(Sequence {
            id: 3,
            class: Application,
            inner: vec![
                   Tag::OctetString(OctetString {
                       inner: base.into_bytes(),
                       .. Default::default()
                   }),
                   Tag::Integer(Integer {
                       inner: scope as i64,
                       .. Default::default()
                   }),
                   Tag::Integer(Integer {
                       inner: deref as i64,
                       .. Default::default()
                   }),
                   Tag::Integer(Integer {
                       inner: 0,
                       .. Default::default()
                   }),
                   Tag::Integer(Integer {
                       inner: 0,
                       .. Default::default()
                   }),
                   Tag::Boolean(Boolean {
                       inner: typesonly,
                       .. Default::default()
                   }),
                   parse(&filter).unwrap(),
                   Tag::Sequence(Sequence {
                       inner: attrs.into_iter().map(|s|
                            Tag::OctetString(OctetString { inner: s.into_bytes(), ..Default::default() })).collect(),
                       .. Default::default()
                   })
            ],
        });

        let (tx, rx) = mpsc::unbounded::<SearchItem>();
        let bundle = bundle(self);
        let fut = self.call(LdapOp::Multi(req, tx.clone())).and_then(move |res| {
            let id = match res {
                (Tag::Integer(Integer { id: _, class: _, inner }), _) => inner,
                _ => unimplemented!(),
            };
            Ok(SearchStream {
                id: id as RequestId,
                bundle: bundle,
                rx: rx,
                refs: Vec::new(),
            })
        });

        Box::new(fut)
    }
}
