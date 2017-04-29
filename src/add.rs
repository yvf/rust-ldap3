use std::collections::HashSet;
use std::convert::AsRef;
use std::hash::Hash;
use std::io;

use asnom::structures::{Tag, Sequence, Set, OctetString};
use asnom::common::TagClass;

use futures::{future, Future};
use tokio_service::Service;

use controls::Control;
use ldap::{Ldap, LdapOp, next_req_controls};
use protocol::LdapResult;

impl Ldap {
    pub fn add<S: AsRef<str> + Eq + Hash>(&self, dn: &str, attrs: Vec<(S, HashSet<S>)>) ->
            Box<Future<Item=(LdapResult, Vec<Control>), Error=io::Error>> {
        let mut any_empty = false;
        let req = Tag::Sequence(Sequence {
            id: 8,
            class: TagClass::Application,
            inner: vec![
                   Tag::OctetString(OctetString {
                       inner: Vec::from(dn.as_bytes()),
                       .. Default::default()
                   }),
                   Tag::Sequence(Sequence {
                       inner: attrs.into_iter().map(|(name, vals)| {
                            if vals.is_empty() {
                                any_empty = true;
                            }
                            Tag::Sequence(Sequence {
                                inner: vec![
                                    Tag::OctetString(OctetString {
                                        inner: Vec::from(name.as_ref()),
                                        .. Default::default()
                                    }),
                                    Tag::Set(Set {
                                        inner: vals.into_iter().map(|v| Tag::OctetString(OctetString {
                                            inner: Vec::from(v.as_ref()),
                                            .. Default::default()
                                        })).collect(),
                                        .. Default::default()
                                    })
                                ],
                                .. Default::default()
                            })
                        }).collect(),
                       .. Default::default()
                   })
            ],
        });
        if any_empty {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "empty value set for Add")));
        }

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|(result, controls)| Ok((result.into(), controls)));

        Box::new(fut)
    }
}
