use std::convert::AsRef;
use std::io;

use asnom::structures::{Tag, OctetString, Sequence};
use asnom::common::TagClass;

use futures::Future;
use tokio_service::Service;

use controls::Control;
use ldap::{Ldap, LdapOp, next_req_controls};
use protocol::LdapResult;

impl Ldap {
    pub fn compare<B: AsRef<[u8]>>(&self, dn: &str, attr: &str, val: B) ->
            Box<Future<Item=(LdapResult, Vec<Control>), Error=io::Error>> {
        let req = Tag::Sequence(Sequence {
            id: 14,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    .. Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: vec! [
                        Tag::OctetString(OctetString {
                            inner: Vec::from(attr.as_bytes()),
                            .. Default::default()
                        }),
                        Tag::OctetString(OctetString {
                            inner: Vec::from(val.as_ref()),
                            .. Default::default()
                        }),
                    ],
                    .. Default::default()
                })
            ],
        });

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|(result, controls)| Ok((result.into(), controls)));

        Box::new(fut)
    }
}
