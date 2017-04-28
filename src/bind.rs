use std::io;

use asnom::structure::StructureTag;
use asnom::structures::{Tag, Sequence, Integer, OctetString};
use asnom::common::TagClass;

use futures::Future;
use tokio_service::Service;

use ldap::{Ldap, LdapOp};
use protocol::LdapResult;

impl Ldap {
    pub fn simple_bind(&self, bind_dn: &str, bind_pw: &str) ->
            Box<Future<Item=(LdapResult, Option<StructureTag>), Error=io::Error>> {
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

        let fut = self.call(LdapOp::Single(req))
            .and_then(|(result, controls)| Ok((result.into(), controls)));

        Box::new(fut)
    }
}
