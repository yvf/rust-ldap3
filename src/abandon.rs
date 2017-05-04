use std::io;

use lber::structures::{Tag, Integer};
use lber::common::TagClass;

use futures::{future, Future};
use tokio_proto::multiplex::RequestId;
use tokio_service::Service;

use ldap::{bundle, Ldap, LdapOp, next_req_controls};

impl Ldap {
    pub fn abandon(&self, id: RequestId) ->
            Box<Future<Item=(), Error=io::Error>> {
        let bundle = bundle(self);
        let msgid = match bundle.borrow().search_helpers.get(&id) {
            Some(helper) => helper.msgid,
            None => return Box::new(future::err(io::Error::new(io::ErrorKind::Other, format!("id {} not a search operation", id)))),
        };
        bundle.borrow_mut().abandoned.insert(id);
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
