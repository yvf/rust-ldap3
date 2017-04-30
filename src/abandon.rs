use std::io;

use asnom::structures::{Tag, Integer};
use asnom::common::TagClass;

use futures::Future;
use tokio_service::Service;

use ldap::{Ldap, LdapOp, next_req_controls};
use protocol::LdapRequestId;

impl Ldap {
    pub fn abandon(&self, msgid: LdapRequestId) ->
            Box<Future<Item=(), Error=io::Error>> {
        let req = Tag::Integer(Integer {
            id: 16,
            class: TagClass::Application,
            inner: msgid as i64
        });

        let fut = self.call(LdapOp::Solo(req, next_req_controls(self)))
            .and_then(|_x| Ok(()));

        Box::new(fut)
    }
}
