use std::io;

use lber::structures::{Tag, Sequence, Integer, OctetString};
use lber::common::TagClass;

use futures::Future;
use tokio_service::Service;

use controls::Control;
use ldap::{Ldap, LdapOp, next_req_controls};
use protocol::LdapResult;

impl Ldap {
    pub fn simple_bind(&self, bind_dn: &str, bind_pw: &str) ->
            Box<Future<Item=(LdapResult, Vec<Control>), Error=io::Error>> {
        let req = Tag::Sequence(Sequence {
            id: 0,
            class: TagClass::Application,
            inner: vec![
                   Tag::Integer(Integer {
                       inner: 3,
                       .. Default::default()
                   }),
                   Tag::OctetString(OctetString {
                       inner: Vec::from(bind_dn),
                       .. Default::default()
                   }),
                   Tag::OctetString(OctetString {
                       id: 0,
                       class: TagClass::Context,
                       inner: Vec::from(bind_pw),
                   })
            ],
        });

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|(result, controls)| Ok((result.into(), controls)));

        Box::new(fut)
    }
}
