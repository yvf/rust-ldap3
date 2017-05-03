use std::io;

use lber::structures::{Boolean, OctetString, Sequence, Tag};
use lber::common::TagClass;

use futures::Future;
use tokio_service::Service;

use controls::Control;
use ldap::{Ldap, LdapOp, next_req_controls};
use protocol::LdapResult;

impl Ldap {
    pub fn modifydn(&self, dn: &str, rdn: &str, delete_old: bool, new_sup: Option<&str>) ->
            Box<Future<Item=(LdapResult, Vec<Control>), Error=io::Error>> {
        let mut params = vec![
           Tag::OctetString(OctetString {
               inner: Vec::from(dn.as_bytes()),
               .. Default::default()
           }),
           Tag::OctetString(OctetString {
               inner: Vec::from(rdn.as_bytes()),
               .. Default::default()
           }),
           Tag::Boolean(Boolean {
               inner: delete_old,
               .. Default::default()
           })
        ];
        if let Some(new_sup) = new_sup {
            params.push(Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(new_sup.as_bytes())
            }));
        }
        let req = Tag::Sequence(Sequence {
            id: 12,
            class: TagClass::Application,
            inner: params
        });

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|(result, controls)| Ok((result.into(), controls)));

        Box::new(fut)
    }
}
