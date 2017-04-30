use std::io;

use asnom::structures::{Tag, Null};
use asnom::common::TagClass;

use futures::Future;
use tokio_service::Service;

use ldap::{Ldap, LdapOp};

impl Ldap {
    pub fn unbind(&self) ->
            Box<Future<Item=(), Error=io::Error>> {
        let req = Tag::Null(Null {
            id: 2,
            class: TagClass::Application,
            inner: ()
        });

        let fut = self.call(LdapOp::Solo(req, None))
            .and_then(|_x| Ok(()));

        Box::new(fut)
    }
}
