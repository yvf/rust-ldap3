use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::controls_impl::IntoRawControlVec;
use crate::exop::Exop;
use crate::exop_impl::construct_exop;
use crate::protocol::{LdapOp, MaybeControls, ResultSender};
use crate::result::{ExopResult, LdapResult, LdapResultExt, Result};
use crate::search::{SearchOptions, SearchStream};
use crate::RequestId;

use lber::common::TagClass;
use lber::structures::{Integer, OctetString, Sequence, Tag};

use tokio::sync::{mpsc, oneshot};
use tokio::time;

#[derive(Debug)]
pub struct Ldap {
    pub(crate) msgmap: Arc<Mutex<(i32, HashSet<i32>)>>,
    pub(crate) tx: mpsc::UnboundedSender<(RequestId, LdapOp, Tag, MaybeControls, ResultSender)>,
    pub(crate) last_id: i32,
    pub(crate) timeout: Option<Duration>,
    pub(crate) controls: MaybeControls,
    pub(crate) search_opts: Option<SearchOptions>,
}

impl Clone for Ldap {
    fn clone(&self) -> Self {
        Ldap {
            msgmap: self.msgmap.clone(),
            tx: self.tx.clone(),
            last_id: 0,
            timeout: None,
            controls: None,
            search_opts: None,
        }
    }
}

impl Ldap {
    fn next_msgid(&mut self) -> i32 {
        let mut msgmap = self.msgmap.lock().expect("msgmap mutex (inc id)");
        let last_ldap_id = msgmap.0;
        let mut next_ldap_id = last_ldap_id;
        loop {
            if next_ldap_id == std::i32::MAX {
                next_ldap_id = 1;
            } else {
                next_ldap_id += 1;
            }
            if !msgmap.1.contains(&next_ldap_id) {
                break;
            }
            assert_ne!(
                next_ldap_id, last_ldap_id,
                "LDAP message id wraparound with no free slots"
            );
        }
        msgmap.0 = next_ldap_id;
        msgmap.1.insert(next_ldap_id);
        next_ldap_id
    }

    pub(crate) async fn op_call(&mut self, op: LdapOp, req: Tag) -> Result<(LdapResult, Exop)> {
        let id = self.next_msgid();
        self.last_id = id;
        let (tx, rx) = oneshot::channel();
        self.tx.send((id, op, req, self.controls.take(), tx))?;
        let response = if let Some(timeout) = self.timeout.take() {
            time::timeout(timeout, rx).await?
        } else {
            rx.await
        }?;
        let (ldap_ext, controls) = (LdapResultExt::from(response.0), response.1);
        let (mut result, exop) = (ldap_ext.0, ldap_ext.1);
        result.ctrls = controls;
        Ok((result, exop))
    }

    pub fn last_id(&mut self) -> RequestId {
        self.last_id
    }

    /// See [`LdapConn::with_search_options()`](struct.LdapConn.html#method.with_search_options).
    pub fn with_search_options(&mut self, opts: SearchOptions) -> &mut Self {
        self.search_opts = Some(opts);
        self
    }

    /// See [`LdapConn::with_controls()`](struct.LdapConn.html#method.with_controls).
    pub fn with_controls<V: IntoRawControlVec>(&mut self, ctrls: V) -> &mut Self {
        self.controls = Some(ctrls.into());
        self
    }

    /// See [`LdapConn::with_timeout()`](struct.LdapConn.html#method.with_timeout).
    pub fn with_timeout(&mut self, duration: Duration) -> &mut Self {
        self.timeout = Some(duration);
        self
    }

    /// See [`LdapConn::simple_bind()`](struct.LdapConn.html#method.simple_bind).
    pub async fn simple_bind(&mut self, bind_dn: &str, bind_pw: &str) -> Result<LdapResult> {
        let req = Tag::Sequence(Sequence {
            id: 0,
            class: TagClass::Application,
            inner: vec![
                Tag::Integer(Integer {
                    inner: 3,
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: Vec::from(bind_dn),
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    id: 0,
                    class: TagClass::Context,
                    inner: Vec::from(bind_pw),
                }),
            ],
        });
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// See [`LdapConn::sasl_external_bind()`](struct.LdapConn.html#method.sasl_external_bind).
    pub async fn sasl_external_bind(&mut self) -> Result<LdapResult> {
        let req = Tag::Sequence(Sequence {
            id: 0,
            class: TagClass::Application,
            inner: vec![
                Tag::Integer(Integer {
                    inner: 3,
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: Vec::new(),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    id: 3,
                    class: TagClass::Context,
                    inner: vec![
                        Tag::OctetString(OctetString {
                            inner: Vec::from("EXTERNAL"),
                            ..Default::default()
                        }),
                        Tag::OctetString(OctetString {
                            inner: Vec::new(),
                            ..Default::default()
                        }),
                    ],
                }),
            ],
        });
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// See [`LdapConn::extended()`](struct.LdapConn.html#method.extended).
    pub async fn extended<E>(&mut self, exop: E) -> Result<ExopResult>
    where
        E: Into<Exop>,
    {
        let req = Tag::Sequence(Sequence {
            id: 23,
            class: TagClass::Application,
            inner: construct_exop(exop.into()),
        });

        self.op_call(LdapOp::Single, req)
            .await
            .map(|et| ExopResult(et.1, et.0))
    }

    pub fn into_search_stream(self) -> SearchStream {
        SearchStream::new(self)
    }
}
