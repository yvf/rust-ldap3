use std::collections::HashSet;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::controls_impl::IntoRawControlVec;
use crate::exop::Exop;
use crate::exop_impl::construct_exop;
use crate::protocol::{LdapOp, MaybeControls, ResultSender};
use crate::result::{
    CompareResult, ExopResult, LdapError, LdapResult, LdapResultExt, Result, SearchResult,
};
use crate::search::parse_refs;
use crate::search::{Scope, SearchOptions, SearchStream};
use crate::RequestId;

use lber::common::TagClass;
use lber::structures::{Boolean, Enumerated, Integer, Null, OctetString, Sequence, Set, Tag};

use maplit::hashset;
use tokio::sync::{mpsc, oneshot};
use tokio::time;

/// Possible sub-operations for the Modify operation.
#[derive(Clone, Debug, PartialEq)]
pub enum Mod<S: AsRef<[u8]> + Eq + Hash> {
    /// Add an attribute, with at least one value.
    Add(S, HashSet<S>),
    /// Delete the entire attribute, or the given values of an attribute.
    Delete(S, HashSet<S>),
    /// Replace an existing attribute, setting its values to those in the set, or delete it if no values are given.
    Replace(S, HashSet<S>),
    /// Increment the attribute by the given value.
    Increment(S, S),
}

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

    pub async fn search<S: AsRef<str>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<S>,
    ) -> Result<SearchResult> {
        let mut stream = self.streaming_search(base, scope, filter, attrs).await?;
        let mut re_vec = vec![];
        let mut refs = vec![];
        while let Some(entry) = stream.next().await? {
            if entry.is_intermediate() {
                continue;
            }
            if entry.is_ref() {
                refs.extend(parse_refs(entry.0));
                continue;
            }
            re_vec.push(entry);
        }
        let mut res = stream.finish();
        res.refs.extend(refs);
        Ok(SearchResult(re_vec, res))
    }

    pub async fn streaming_search<S: AsRef<str>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<S>,
    ) -> Result<SearchStream> {
        SearchStream::new(self.clone())
            .start(base, scope, filter, attrs)
            .await
    }

    /// See [`LdapConn::add()`](struct.LdapConn.html#method.add).
    pub async fn add<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        attrs: Vec<(S, HashSet<S>)>,
    ) -> Result<LdapResult> {
        let mut any_empty = false;
        let req = Tag::Sequence(Sequence {
            id: 8,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: attrs
                        .into_iter()
                        .map(|(name, vals)| {
                            if vals.is_empty() {
                                any_empty = true;
                            }
                            Tag::Sequence(Sequence {
                                inner: vec![
                                    Tag::OctetString(OctetString {
                                        inner: Vec::from(name.as_ref()),
                                        ..Default::default()
                                    }),
                                    Tag::Set(Set {
                                        inner: vals
                                            .into_iter()
                                            .map(|v| {
                                                Tag::OctetString(OctetString {
                                                    inner: Vec::from(v.as_ref()),
                                                    ..Default::default()
                                                })
                                            })
                                            .collect(),
                                        ..Default::default()
                                    }),
                                ],
                                ..Default::default()
                            })
                        })
                        .collect(),
                    ..Default::default()
                }),
            ],
        });
        if any_empty {
            return Err(LdapError::AddNoValues);
        }
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// See [`LdapConn::compare()`](struct.LdapConn.html#method.compare).
    pub async fn compare<B: AsRef<[u8]>>(
        &mut self,
        dn: &str,
        attr: &str,
        val: B,
    ) -> Result<CompareResult> {
        let req = Tag::Sequence(Sequence {
            id: 14,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: vec![
                        Tag::OctetString(OctetString {
                            inner: Vec::from(attr.as_bytes()),
                            ..Default::default()
                        }),
                        Tag::OctetString(OctetString {
                            inner: Vec::from(val.as_ref()),
                            ..Default::default()
                        }),
                    ],
                    ..Default::default()
                }),
            ],
        });
        Ok(CompareResult(self.op_call(LdapOp::Single, req).await?.0))
    }

    /// See [`LdapConn::delete()`](struct.LdapConn.html#method.delete).
    pub async fn delete(&mut self, dn: &str) -> Result<LdapResult> {
        let req = Tag::OctetString(OctetString {
            id: 10,
            class: TagClass::Application,
            inner: Vec::from(dn.as_bytes()),
        });
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// See [`LdapConn::modify()`](struct.LdapConn.html#method.modify).
    pub async fn modify<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        mods: Vec<Mod<S>>,
    ) -> Result<LdapResult> {
        let mut any_add_empty = false;
        let req = Tag::Sequence(Sequence {
            id: 6,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(dn.as_bytes()),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    inner: mods
                        .into_iter()
                        .map(|m| {
                            let mut is_add = false;
                            let (num, attr, set) = match m {
                                Mod::Add(attr, set) => {
                                    is_add = true;
                                    (0, attr, set)
                                }
                                Mod::Delete(attr, set) => (1, attr, set),
                                Mod::Replace(attr, set) => (2, attr, set),
                                Mod::Increment(attr, val) => (3, attr, hashset! { val }),
                            };
                            if set.is_empty() && is_add {
                                any_add_empty = true;
                            }
                            let op = Tag::Enumerated(Enumerated {
                                inner: num,
                                ..Default::default()
                            });
                            let part_attr = Tag::Sequence(Sequence {
                                inner: vec![
                                    Tag::OctetString(OctetString {
                                        inner: Vec::from(attr.as_ref()),
                                        ..Default::default()
                                    }),
                                    Tag::Set(Set {
                                        inner: set
                                            .into_iter()
                                            .map(|val| {
                                                Tag::OctetString(OctetString {
                                                    inner: Vec::from(val.as_ref()),
                                                    ..Default::default()
                                                })
                                            })
                                            .collect(),
                                        ..Default::default()
                                    }),
                                ],
                                ..Default::default()
                            });
                            Tag::Sequence(Sequence {
                                inner: vec![op, part_attr],
                                ..Default::default()
                            })
                        })
                        .collect(),
                    ..Default::default()
                }),
            ],
        });
        if any_add_empty {
            return Err(LdapError::AddNoValues);
        }
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// See [`LdapConn::modifydn()`](struct.LdapConn.html#method.modifydn).
    pub async fn modifydn(
        &mut self,
        dn: &str,
        rdn: &str,
        delete_old: bool,
        new_sup: Option<&str>,
    ) -> Result<LdapResult> {
        let mut params = vec![
            Tag::OctetString(OctetString {
                inner: Vec::from(dn.as_bytes()),
                ..Default::default()
            }),
            Tag::OctetString(OctetString {
                inner: Vec::from(rdn.as_bytes()),
                ..Default::default()
            }),
            Tag::Boolean(Boolean {
                inner: delete_old,
                ..Default::default()
            }),
        ];
        if let Some(new_sup) = new_sup {
            params.push(Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(new_sup.as_bytes()),
            }));
        }
        let req = Tag::Sequence(Sequence {
            id: 12,
            class: TagClass::Application,
            inner: params,
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

    /// See [`LdapConn::unbind()`](struct.LdapConn.html#method.unbind).
    pub async fn unbind(&mut self) -> Result<()> {
        let req = Tag::Null(Null {
            id: 2,
            class: TagClass::Application,
            inner: (),
        });
        Ok(self.op_call(LdapOp::Unbind, req).await.map(|_| ())?)
    }

    pub fn last_id(&mut self) -> RequestId {
        self.last_id
    }

    pub async fn abandon(&mut self, msgid: RequestId) -> Result<()> {
        let req = Tag::Integer(Integer {
            id: 16,
            class: TagClass::Application,
            inner: msgid as i64,
        });
        Ok(self
            .op_call(LdapOp::Abandon(msgid), req)
            .await
            .map(|_| ())?)
    }
}
