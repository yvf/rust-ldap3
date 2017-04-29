use std::collections::HashSet;
use std::convert::AsRef;
use std::hash::Hash;
use std::io;

use asnom::structures::{Tag, Enumerated, Sequence, Set, OctetString};
use asnom::common::TagClass;

use futures::{future, Future};
use tokio_service::Service;

use controls::Control;
use ldap::{Ldap, LdapOp, next_req_controls};
use protocol::LdapResult;

#[derive(Clone, Debug, PartialEq)]
pub enum Mod<S: AsRef<str> + Eq + Hash> {
    Add(S, HashSet<S>),
    Delete(S, HashSet<S>),
    Replace(S, HashSet<S>),
}

impl Ldap {
    pub fn modify<S: AsRef<str> + Eq + Hash>(&self, dn: &str, mods: Vec<Mod<S>>) ->
            Box<Future<Item=(LdapResult, Vec<Control>), Error=io::Error>> {
        let mut any_add_empty = false;
        let req = Tag::Sequence(Sequence {
            id: 6,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    .. Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: mods.into_iter().map(|m| {
                        let mut is_add = false;
                        let (num, attr, set) = match m {
                            Mod::Add(attr, set) => { is_add = true; (0, attr, set) },
                            Mod::Delete(attr, set) => (1, attr, set),
                            Mod::Replace(attr, set) => (2, attr, set),
                        };
                        if set.is_empty() && is_add {
                            any_add_empty = true;
                        }
                        let op = Tag::Enumerated(Enumerated {
                            inner: num,
                            .. Default::default()
                        });
                        let part_attr = Tag::Sequence(Sequence {
                            inner: vec![
                                Tag::OctetString(OctetString {
                                    inner: Vec::from(attr.as_ref()),
                                    .. Default::default()
                                }),
                                Tag::Set(Set {
                                    inner: set.into_iter().map(|val| {
                                        Tag::OctetString(OctetString {
                                            inner: Vec::from(val.as_ref()),
                                            .. Default::default()
                                        })
                                    }).collect(),
                                    .. Default::default()
                                })
                            ],
                            .. Default::default()
                        });
                        Tag::Sequence(Sequence {
                            inner: vec![op, part_attr],
                            .. Default::default()
                        })
                    }).collect(),
                    .. Default::default()
                })
            ]
        });
        if any_add_empty {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "empty value set for Add")));
        }

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|(result, controls)| Ok((result.into(), controls)));

        Box::new(fut)
    }
}
