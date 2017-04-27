use std::convert::AsRef;
use std::io;

use asnom::structure::StructureTag;
use asnom::structures::{Tag, OctetString};
use asnom::common::TagClass;

use futures::Future;
use tokio_service::Service;

use ldap::{Ldap, LdapOp};
use protocol::LdapResult;

impl Ldap {
    pub fn delete<S: AsRef<str>>(&self, dn: S) ->
        Box<Future<Item=(LdapResult, Option<StructureTag>), Error=io::Error>> {
        let req = Tag::OctetString(OctetString {
            id: 10,
            class: TagClass::Application,
            inner: Vec::from(dn.as_ref())
        });

        let fut = self.call(LdapOp::Single(req))
            .and_then(|(result, controls)| Ok((result.into(), controls)));

        Box::new(fut)
    }
}
