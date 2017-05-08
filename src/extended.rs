use std::io;

use lber::structures::{Tag, Sequence};
use lber::common::TagClass;

use futures::Future;
use tokio_service::Service;

use controls::Control;
use ldap::{Ldap, LdapOp, next_req_controls};
use exop::Exop;
use protocol::{LdapResult, LdapResultExt};

impl Ldap {
    /// See [`LdapConn::extended()`](struct.LdapConn.html#method.extended).
    pub fn extended<E>(&self, exop: E) ->
        Box<Future<Item=(LdapResult, Exop, Vec<Control>), Error=io::Error>>
        where Vec<Tag>: From<E>
    {
        let req = Tag::Sequence(Sequence {
            id: 23,
            class: TagClass::Application,
            inner: exop.into()
        });

        let fut = self.call(LdapOp::Single(req, next_req_controls(self)))
            .and_then(|(result, controls)| {
                let result_ext: LdapResultExt = result.into();
                Ok((result_ext.0, result_ext.1, controls))
            });

        Box::new(fut)
    }
}
