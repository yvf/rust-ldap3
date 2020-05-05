use std::collections::HashMap;
use std::time::Duration;

use crate::controls::Control;
use crate::ldap::Ldap;
use crate::parse_filter;
use crate::protocol::LdapOp;
use crate::result::{LdapError, LdapResult, Result};
use crate::RequestId;

use tokio::sync::mpsc;
use tokio::time;

use lber::common::TagClass;
use lber::structure::StructureTag;
use lber::structures::{Boolean, Enumerated, Integer, OctetString, Sequence, Tag};

/// Possible values for search scope.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Scope {
    /// Base object; search only the object named in the base DN.
    Base = 0,
    /// Search the objects immediately below the base DN.
    OneLevel = 1,
    /// Search the object named in the base DN and the whole subtree below it.
    Subtree = 2,
}

/// Possible values for alias dereferencing during search.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DerefAliases {
    /// Never dereference.
    Never = 0,
    /// Dereference while retrieving objects according to search scope.
    Searching = 1,
    /// Dereference while finding the base object.
    Finding = 2,
    /// Always dereference.
    Always = 3,
}

impl Default for DerefAliases {
    fn default() -> Self {
        DerefAliases::Never
    }
}

#[derive(Debug)]
pub enum SearchItem {
    Entry(StructureTag),
    Referral(StructureTag),
    Done(LdapResult),
}

/// Wrapper for the internal structure of a result entry.
#[derive(Debug, Clone)]
pub struct ResultEntry(pub StructureTag, pub Vec<Control>);

impl ResultEntry {
    #[doc(hidden)]
    pub fn new(st: StructureTag) -> ResultEntry {
        ResultEntry(st, vec![])
    }

    /// Returns true if the enclosed entry is a referral.
    pub fn is_ref(&self) -> bool {
        self.0.id == 19
    }

    /// Returns true if the enclosed entry is an intermediate message.
    pub fn is_intermediate(&self) -> bool {
        self.0.id == 25
    }
}

/// Additional parameters for the Search operation.
#[derive(Clone, Debug, Default)]
pub struct SearchOptions {
    pub(crate) deref: DerefAliases,
    pub(crate) typesonly: bool,
    pub(crate) timelimit: i32,
    pub(crate) sizelimit: i32,
}

impl SearchOptions {
    /// Create an instance of the structure with default values.
    pub fn new() -> Self {
        SearchOptions {
            ..Default::default()
        }
    }

    /// Set the method for dereferencing aliases.
    pub fn deref(mut self, d: DerefAliases) -> Self {
        self.deref = d;
        self
    }

    /// Set the indicator of returning just attribute names (`true`) vs. names and values (`false`).
    pub fn typesonly(mut self, typesonly: bool) -> Self {
        self.typesonly = typesonly;
        self
    }

    /// Set the time limit, in seconds, for the whole search operation.
    ///
    /// This is a server-side limit of the elapsed time for performing the operation, _not_ a
    /// network timeout for retrieving result entries or the result of the whole operation.
    pub fn timelimit(mut self, timelimit: i32) -> Self {
        self.timelimit = timelimit;
        self
    }

    /// Set the size limit, in entries, for the whole search operation.
    pub fn sizelimit(mut self, sizelimit: i32) -> Self {
        self.sizelimit = sizelimit;
        self
    }
}

/// Parsed search result entry.
///
/// While LDAP attributes can have a variety of syntaxes, they're all returned in
/// search results as octet strings, without any associated type information. A
/// general-purpose result parser could leave all values in that format, but then
/// retrieving them from user code would be cumbersome and tedious.
///
/// For that reason, the parser tries to convert every value into a `String`. If an
/// attribute can contain unconstrained binary strings, the conversion may fail. In that case,
/// the attribute and all its values will be in the `bin_attrs` hashmap. Since it's
/// possible that a particular set of values for a binary attribute _could_ be
/// converted into UTF-8 `String`s, the presence of of such attribute in the result
/// entry should be checked for both in `attrs` and `bin_atrrs`.
#[derive(Debug, Clone)]
pub struct SearchEntry {
    /// Entry DN.
    pub dn: String,
    /// Attributes.
    pub attrs: HashMap<String, Vec<String>>,
    /// Binary-valued attributes.
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl SearchEntry {
    /// Parse raw BER data and convert it into attribute map(s).
    ///
    /// __Note__: this function will panic on parsing error.
    pub fn construct(re: ResultEntry) -> SearchEntry {
        let mut tags =
            re.0.match_id(4)
                .and_then(|t| t.expect_constructed())
                .expect("entry")
                .into_iter();
        let dn = String::from_utf8(
            tags.next()
                .expect("element")
                .expect_primitive()
                .expect("octet string"),
        )
        .expect("dn");
        let mut attr_vals = HashMap::new();
        let mut bin_attr_vals = HashMap::new();
        let attrs = tags
            .next()
            .expect("element")
            .expect_constructed()
            .expect("attrs")
            .into_iter();
        for a_v in attrs {
            let mut part_attr = a_v
                .expect_constructed()
                .expect("partial attribute")
                .into_iter();
            let a_type = String::from_utf8(
                part_attr
                    .next()
                    .expect("element")
                    .expect_primitive()
                    .expect("octet string"),
            )
            .expect("attribute type");
            let mut any_binary = false;
            let values = part_attr
                .next()
                .expect("element")
                .expect_constructed()
                .expect("values")
                .into_iter()
                .map(|t| t.expect_primitive().expect("octet string"))
                .filter_map(|s| {
                    if let Ok(s) = std::str::from_utf8(s.as_ref()) {
                        return Some(s.to_owned());
                    }
                    bin_attr_vals
                        .entry(a_type.clone())
                        .or_insert_with(|| vec![])
                        .push(s);
                    any_binary = true;
                    None
                })
                .collect::<Vec<String>>();
            if any_binary {
                bin_attr_vals.get_mut(&a_type).expect("bin vector").extend(
                    values
                        .into_iter()
                        .map(String::into_bytes)
                        .collect::<Vec<Vec<u8>>>(),
                );
            } else {
                attr_vals.insert(a_type, values);
            }
        }
        SearchEntry {
            dn,
            attrs: attr_vals,
            bin_attrs: bin_attr_vals,
        }
    }
}

/// Asynchronous handle for obtaining a stream of search results. __*__
///
/// A streaming search should be used for situations where the expected
/// size of result entries varies considerably between searches, and/or
/// can rise above a few tens to hundreds of KB. This is more of a concern
/// for a long-lived process which is expected to have a predictable memory
/// footprint (i.e., a server), but can also help with one-off searches if
/// the result set is in the tens of thounsands of entries.
///
/// Once initiated, a streaming search is driven to the end by repeatedly calling
/// [`next()`](#method.next) until it returns `Ok(None)` or an error. Then, a call
/// to [`finish()`](#method.finish) will return the overall result of the search.
/// Calling `finish()` earlier will terminate search result processing in the
/// client; it is the user's responsibility to inform the server that the operation
/// has been terminated by sending an Abandon or a Cancel operation.
#[derive(Debug)]
pub struct SearchStream {
    ldap: Ldap,
    rx: Option<mpsc::UnboundedReceiver<(SearchItem, Vec<Control>)>>,
    req: Option<Tag>,
    timeout: Option<Duration>,
    res: Option<LdapResult>,
}

impl SearchStream {
    pub(crate) fn new(ldap: Ldap) -> Self {
        SearchStream {
            ldap,
            rx: None,
            req: None,
            timeout: None,
            res: None,
        }
    }

    pub(crate) async fn start<S: AsRef<str>>(
        mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<S>,
    ) -> Result<Self> {
        let opts = match self.ldap.search_opts.take() {
            Some(opts) => opts,
            None => SearchOptions::new(),
        };
        self.timeout = self.ldap.timeout.take();
        let req = Tag::Sequence(Sequence {
            id: 3,
            class: TagClass::Application,
            inner: vec![
                Tag::OctetString(OctetString {
                    inner: Vec::from(base.as_bytes()),
                    ..Default::default()
                }),
                Tag::Enumerated(Enumerated {
                    inner: scope as i64,
                    ..Default::default()
                }),
                Tag::Enumerated(Enumerated {
                    inner: opts.deref as i64,
                    ..Default::default()
                }),
                Tag::Integer(Integer {
                    inner: opts.sizelimit as i64,
                    ..Default::default()
                }),
                Tag::Integer(Integer {
                    inner: opts.timelimit as i64,
                    ..Default::default()
                }),
                Tag::Boolean(Boolean {
                    inner: opts.typesonly,
                    ..Default::default()
                }),
                match parse_filter(filter) {
                    Ok(filter) => filter,
                    _ => return Err(LdapError::FilterParsing),
                },
                Tag::Sequence(Sequence {
                    inner: attrs
                        .into_iter()
                        .map(|s| {
                            Tag::OctetString(OctetString {
                                inner: Vec::from(s.as_ref()),
                                ..Default::default()
                            })
                        })
                        .collect(),
                    ..Default::default()
                }),
            ],
        });
        let (tx, rx) = mpsc::unbounded_channel();
        self.rx = Some(rx);
        if let Some(ref timeout) = self.timeout {
            self.ldap.with_timeout(*timeout);
        }
        self.ldap.op_call(LdapOp::Search(tx), req).await?;
        Ok(self)
    }

    /// Fetch the next item from the result stream.
    ///
    /// Returns Ok(None) at the end of the stream.
    #[allow(clippy::should_implement_trait)]
    pub async fn next(&mut self) -> Result<Option<ResultEntry>> {
        if self.rx.is_none() {
            return Ok(None);
        }
        let item = if let Some(ref timeout) = self.timeout {
            let res = time::timeout(*timeout, self.rx.as_mut().unwrap().recv()).await;
            if res.is_err() {
                let last_id = self.ldap.last_id;
                self.ldap.id_scrub_tx.send(last_id)?;
            }
            res?
        } else {
            self.rx.as_mut().unwrap().recv().await
        };
        let (item, controls) = match item {
            Some((item, controls)) => (item, controls),
            None => {
                self.rx = None;
                return Err(LdapError::EndOfStream);
            }
        };
        match item {
            SearchItem::Entry(tag) | SearchItem::Referral(tag) => {
                return Ok(Some(ResultEntry(tag, controls)))
            }
            SearchItem::Done(mut res) => {
                res.ctrls = controls;
                self.res = Some(res);
                self.rx = None;
            }
        }
        Ok(None)
    }

    /// Return the overall result of the Search.
    ///
    /// This method can be called at any time. If the stream has been read to the
    /// end, the return value will be the actual result returned by the server.
    /// Otherwise, a synthetic cancellation result is returned, and it's the user's
    /// responsibility to abandon or cancel the operation on the server.
    pub fn finish(mut self) -> LdapResult {
        if self.rx.is_some() {
            let last_id = self.ldap.last_id;
            if let Err(e) = self.ldap.id_scrub_tx.send(last_id) {
                warn!(
                    "error sending scrub message from SearchStream::finish() for ID {}: {}",
                    last_id, e
                );
            }
        }
        self.rx = None;
        self.res.unwrap_or_else(|| LdapResult {
            rc: 88,
            matched: String::from(""),
            text: String::from("user cancelled"),
            refs: vec![],
            ctrls: vec![],
        })
    }

    /// Return the message ID of the Search operation.
    pub fn last_id(&mut self) -> RequestId {
        self.ldap.last_id()
    }
}

/// Parse the referrals from the supplied BER-encoded sequence.
pub fn parse_refs(t: StructureTag) -> Vec<String> {
    t.expect_constructed()
        .expect("referrals")
        .into_iter()
        .map(|t| t.expect_primitive().expect("octet string"))
        .map(String::from_utf8)
        .map(|s| s.expect("uri"))
        .collect()
}
