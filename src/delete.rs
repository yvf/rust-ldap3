use std::io;

use lber::structures::{Tag, OctetString};
use lber::common::TagClass;

use futures::Future;
use tokio_service::Service;

use controls::Control;
use ldap::{Ldap, LdapOp, next_req_controls};
use protocol::LdapResult;

impl Ldap {
    pub fn delete(&self, dn: &str) ->
            Box<Future<Item=(LdapResult, Vec<Control>), Error=io::Error>> {
        let req = Tag::OctetString(OctetString {
            id: 10,
            class: TagClass::Application,
            inner: Vec::from(dn.as_bytes())
        });

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|(result, controls)| Ok((result.into(), controls)));

        Box::new(fut)
    }
}
