#[cfg(unix)]
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::convert::AsRef;
use std::hash::Hash;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::rc::Rc;

use futures::{Async, Future, Poll, Stream};
use futures::future::Shared;
use futures::sync::oneshot;
use tokio_core::reactor::{Core, Handle};
use tokio_proto::multiplex::RequestId;
use url::{Host, Url};
#[cfg(unix)]
use url::percent_encoding::percent_decode;

use lber::structure::StructureTag;
use lber::structures::Tag;
use controls::Control;
use exop::Exop;
use ldap::Ldap;
use modify::Mod;
use protocol::LdapResult;
use search::{SearchOptions, SearchStream, Scope};

struct LdapWrapper {
    inner: Ldap,
}

impl LdapWrapper {
    fn ldap(&self) -> Ldap {
        self.inner.clone()
    }

    fn connect(addr: &SocketAddr, handle: &Handle) -> Box<Future<Item=LdapWrapper, Error=io::Error>> {
        let lw = Ldap::connect(addr, handle)
            .map(|ldap| {
                LdapWrapper {
                    inner: ldap,
                }
            });
        Box::new(lw)
    }

    fn connect_ssl(addr: &str, handle: &Handle) -> Box<Future<Item=LdapWrapper, Error=io::Error>> {
        let lw = Ldap::connect_ssl(addr, handle)
            .map(|ldap| {
                LdapWrapper {
                    inner: ldap,
                }
            });
        Box::new(lw)
    }

    fn connect_unix(path: &str, handle: &Handle) -> Box<Future<Item=LdapWrapper, Error=io::Error>> {
        let lw = Ldap::connect_unix(path, handle)
            .map(|ldap| {
                LdapWrapper {
                    inner: ldap,
                }
            });
        Box::new(lw)
    }
}

/// Handle for obtaining a stream of search results.
///
/// A streaming search should be used for situations where the expected
/// size of result entries varies considerably between searches, and/or
/// can rise above a few tens to hundreds of KB. This is more of a concern
/// for a long-lived process which is expected to have a predictable memory
/// footprint (i.e., a server), but can also help with one-off searches if
/// the result set is in the tens of thounsands of entries.
///
/// Once initiated, a streaming search must either be driven to the end by
/// repeatedly calling [`next()`](#method.next) until it returns `Ok(None)`
/// or an Error, or cancelled by calling [`abandon()`](struct.LdapConn.html#method.abandon)
/// with the request id obtained by calling [`id()`](#method.id) on the
/// stream handle.
///
/// After regular termination or cancellation, the overall result of the
/// search _must_ be retrieved by calling [`result()`](#method.result) on
/// the stream handle.
pub struct EntryStream {
    core: Rc<RefCell<Core>>,
    strm: Option<SearchStream>,
    rx_r: Option<oneshot::Receiver<(LdapResult, Vec<Control>)>>,
}

impl EntryStream {
    /// Retrieve the next search result. `Ok(None)` signals the end of the
    /// stream.
    // next() is quite fitting here, but we can't implement Iterator directly on this structure;
    // it mustn't be possible to move it out through into_iter(), as we need it to retrieve LdapResult
    // after iteration. Implementing Iterator on a helper is an option, but the semantics of termination
    // in case of Err(_) should be explored first
    #[cfg_attr(feature="cargo-clippy", allow(should_implement_trait))]
    pub fn next(&mut self) -> io::Result<Option<StructureTag>> {
        let strm = self.strm.take();
        if strm.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "cannot fetch from an invalid stream"));
        }
        let (tag, strm) = self.core.borrow_mut().run(strm.expect("stream").into_future()).map_err(|e| e.0)?;
        self.strm = Some(strm);
        Ok(tag)
    }

    /// Retrieve the overall result of the search. This method must be
    /// called _after_ the stream has terminated by returning `Ok(None)` or
    /// an error, although the latter case is guaranteed to also return an
    /// error. If this protocol is not followed, the method will hang.
    pub fn result(&mut self) -> io::Result<(LdapResult, Vec<Control>)> {
        if self.strm.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "cannot return result from an invalid stream"));
        }
        let rx_r = self.rx_r.take().expect("oneshot rx");
        let res = self.core.borrow_mut().run(rx_r).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        Ok(res)
    }

    /// Get the internal `RequestId` of the search, which can be used to
    /// abandon it. The method returns `None` if the stream is in the
    /// errored state at the time of call.
    ///
    /// __Note__: this method will probably be deprecated or removed in
    /// the 0.5.x version of the library, in favor of directly calling
    /// `abandon()` on the stream.
    pub fn id(&mut self) -> Option<RequestId> {
        if let Some(ref strm) = self.strm {
            Some(strm.id())
        } else {
            None
        }
    }
}

/// Handle for LDAP operations. __Entry point for the synchronous interface__.
///
/// A connection is opened by calling [`new()`](#method.new). If successful, this returns
/// a handle which is used for all subsequent operations on that connection. Authenticating
/// the user can be done with [`simple_bind()`](#method.simple_bind) or [`sasl_external_bind()`]
/// (#method.sasl_external_bind); the latter is available on Unix-like systems, and can only
/// work on Unix domain socket connections.
///
/// All LDAP operations allow attaching a series of request controls, which augment or modify
/// the operation. Controls are attached by calling [`with_controls()`](#method.with_controls)
/// on the handle, and using the result to call another modifier or the operation itself.
///
/// The Search operation has many parameters, most of which are infrequently used. Those
/// parameters can be specified by constructing a [`SearchOptions`](struct.SearchOptions.html)
/// structure and passing it to [`with_search_options()`](#method.with_serach_options)
/// called on the handle. This method can be combined with `with_controls()`, described above.
///
/// There are two ways to invoke a search. The first, using [`search()`](#method.search),
/// returns all result entries in a single vector, which works best if it's known that the
/// result set will be limited. The other way uses [`streaming_search()`](#method.streaming_search),
/// which accepts the same parameters, but returns a handle which must be used to obtain
/// result entries one by one.
///
/// As a rule, operations return a [`LdapResult`](struct.LdapResult.html) and a vector of
/// response controls. `LdapResult` is a structure with result components, the most important
/// of which is the result code, a numeric value indicating the outcome of the operation.
/// Controls are not directly usable, and must be additionally parsed by the driver- or
/// user-supplied code.
///
/// __Note__: controls are presently returned as a separate element of a tuple. The next
/// version of the library, 0.5.x, will probably change this to incorporate response
/// controls into `LdapResult`.
#[derive(Clone)]
pub struct LdapConn {
    core: Rc<RefCell<Core>>,
    inner: Ldap,
}

impl LdapConn {
    /// Open a connection to an LDAP server specified by `url`. For the
    /// details of supported URL formats, see
    /// [`LdapConnAsync::new()`](struct.LdapConnAsync.html#method.new).
    pub fn new(url: &str) -> io::Result<Self> {
        let mut core = Core::new()?;
        let conn = LdapConnAsync::new(url, &core.handle())?;
        let ldap = core.run(conn)?;
        Ok(LdapConn {
            core: Rc::new(RefCell::new(core)),
            inner: ldap,
        })
    }

    /// Do a simple Bind with the provided DN (`bind_dn`) and password (`bind_pw`).
    pub fn simple_bind(&self, bind_dn: &str, bind_pw: &str) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().simple_bind(bind_dn, bind_pw))?)
    }

    #[cfg(unix)]
    /// Do a SASL EXTERNAL bind on the connection. Presently, it only makes sense
    /// on Unix domain socket connections. The bind is made with the hardcoded
    /// empty authzId value.
    pub fn sasl_external_bind(&self) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().sasl_external_bind())?)
    }

    /// Use the provided `SearchOptions` with the next Search operation, which can
    /// be invoked directly on the result of this method. If this method is used in
    /// combination with a non-Search operation, the provided options will be silently
    /// discarded when the operation is invoked.
    pub fn with_search_options(&self, opts: SearchOptions) -> &Self {
        self.inner.with_search_options(opts);
        self
    }

    /// Pass the provided vector of request controls to the next LDAP operation.
    /// Controls can be constructed by instantiating structs in the [`controls`]
    /// (controls/index.html) module, and converted to the form needed by this
    /// method by calling `into()` on the instances. See the module-level
    /// documentation for the list of directly supported controls and procedures
    /// for defining custom controls.
    ///
    /// The desired operation can be invoked on the result of this method.
    pub fn with_controls(&self, ctrls: Vec<StructureTag>) -> &Self {
        self.inner.with_controls(ctrls);
        self
    }

    /// Perform a Search with the given base DN (`base`), scope, filter, and
    /// the list of attributes to be returned (`attrs`). If `attrs` is empty,
    /// or if it contains a special name `*` (asterisk), return all (user) attributes.
    /// Requesting a special name `+` (plus sign) will return all operational
    /// attributes. Include both `*` and `+` in order to return all attributes
    /// of an entry.
    ///
    /// The first member of the returned tuple will be the vector of all result
    /// entries. Entries are not directly usable, and must be parsed by
    /// [`SearchEntry::construct()`](struct.SearchEntry.html#method.construct).
    ///
    /// This method should be used if it's known that the result set won't be
    /// large. For other situations, one can use [`streaming_search()`](#method.streaming_search).
    ///
    /// The asynchronous method of the same name works differently: it returns a
    /// stream handle which must be iterated through to obtain result entries.
    pub fn search<S: AsRef<str>>(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<S>) -> io::Result<(Vec<StructureTag>, LdapResult, Vec<Control>)> {
        let srch = self.inner.clone().search(base, scope, filter, attrs)
            .and_then(|(strm, rx_r)| {
                rx_r.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
                    .join(strm.collect())
            });
        let ((result, controls), result_set) = self.core.borrow_mut().run(srch)?;
        Ok((result_set, result, controls))
    }

    /// Perform a Search, but unlike [`search()`](#method.search) (q.v., also for
    /// the parameters), which returns all results at once, return a handle which
    /// will be used for retrieving entries one by one. See [`EntryStream`](struct.EntryStream.html)
    /// for the explanation of the protocol which must be adhered to in this case.
    ///
    /// In the asynchronous interface, this method doesn't exist; there, _all_ searches
    /// are streaming.
    pub fn streaming_search<S: AsRef<str>>(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<S>) -> io::Result<EntryStream> {
        let (strm, rx_r) = self.core.borrow_mut().run(self.inner.clone().search(base, scope, filter, attrs))?;
        Ok(EntryStream { core: self.core.clone(), strm: Some(strm), rx_r: Some(rx_r) })
    }

    /// Add an entry named by `dn`, with the list of attributes and their values
    /// given in `attrs`. None of the `HashSet`s of values for an attribute may
    /// be empty.
    pub fn add<S: AsRef<str> + Eq + Hash>(&self, dn: &str, attrs: Vec<(S, HashSet<S>)>) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().add(dn, attrs))?)
    }

    /// Delete an entry named by `dn`.
    pub fn delete(&self, dn: &str) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().delete(dn))?)
    }

    /// Modify an entry named by `dn`, by sequentially applying the modifications given by `mods`.
    /// See the [`Mod`](enum.Mod.html) documentation for the description of possible values.
    pub fn modify<S: AsRef<str> + Eq + Hash>(&self, dn: &str, mods: Vec<Mod<S>>) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().modify(dn, mods))?)
    }

    /// Rename and/or move an entry named by `dn`. The new name is given by `rdn`. If
    /// `delete_old` is `true`, delete the previous value of the naming attribute from
    /// the entry. If the entry is to be moved elsewhere in the DIT, `new_sup` gives
    /// the new superior entry where the moved entry will be anchored.
    pub fn modifydn(&self, dn: &str, rdn: &str, delete_old: bool, new_sup: Option<&str>) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().modifydn(dn, rdn, delete_old, new_sup))?)
    }

    /// Terminate the connection to the server.
    pub fn unbind(&self) -> io::Result<()> {
        Ok(self.core.borrow_mut().run(self.inner.clone().unbind())?)
    }

    /// Compare the value(s) of the attribute `attr` within an entry named by `dn` with the
    /// value `val`. If any of the values is identical to the provided one, return result code 5
    /// (`compareTrue`), otherwise return result code 6 (`compareFalse`). If access control
    /// rules on the server disallow comparison, another result code will be used to indicate
    /// an error.
    pub fn compare<B: AsRef<[u8]>>(&self, dn: &str, attr: &str, val: B) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().compare(dn, attr, val))?)
    }

    /// Perform an Extended operation given by `exop`. Extended operations are defined in the
    /// [`exop`](exop.html) module. See the module-level documentation for the list of extended
    /// operations supported by this library and procedures for defining custom exops.
    ///
    /// __Note__: the order of return values for this method is wrong, and will change in
    /// version 0.5.x. So will the type of `exop`.
    pub fn extended<E>(&self, exop: E) -> io::Result<(LdapResult, Exop, Vec<Control>)>
        where Vec<Tag>: From<E>
    {
        Ok(self.core.borrow_mut().run(self.inner.clone().extended(exop))?)
    }

    /// Ask the server to terminate the operation, identified here by the library-internal
    /// parameter `id`. Only active streaming searches can be abandoned by this
    /// implementation.
    ///
    /// __Note__: this method will probably be deprecated or removed in
    /// the 0.5.x version of the library, in favor of directly calling
    /// `abandon()` on the search stream.
    pub fn abandon(&self, id: RequestId) -> io::Result<()> {
        Ok(self.core.borrow_mut().run(self.inner.clone().abandon(id))?)
    }
}

/// Asynchronous handle for LDAP operations; analogue of `LdapConn`. __*__
///
/// An instance of this structure is constructed analogously to `LdapConn`. However,
/// that instance can't be used to directly invoke LDAP operations; it must first be
/// resolved as a future to yield a handle which will be used for that purpose.
///
/// To reuse the same connection for multiple operations, a `LdapConnAsync` instance
/// can be `clone()`d.
///
/// ### Example
///
/// ```rust,no_run
/// use std::io;
/// use ldap3::LdapConnAsync;
///
/// # fn _x() -> io::Result<()> {
/// let ldap = LdapConnAsync::new("ldap://localhost:2389")?;
/// let bind = ldap.clone().and_then(|ldap| {
///     ldap.simple_bind(
///         "uid=test,ou=People,dc=example,dc=org",
///         "triplesecret"
///     )
///     .and_then(|(res, _ctrls)| Ok(res));
/// # }
/// ```
#[derive(Clone)]
pub struct LdapConnAsync {
    in_progress: Shared<Box<Future<Item=LdapWrapper, Error=io::Error>>>,
}

impl LdapConnAsync {
    #[cfg(not(unix))]
    /// Open a connection to an LDAP server specified by `url`. This is an LDAP URL, from
    /// which the scheme (__ldap__ or __ldaps__), host, and port are used.
    pub fn new(url: &str, handle: &Handle) -> io::Result<Self> {
        LdapConnAsync::new_tcp(url, handle)
    }

    #[cfg(unix)]
    /// Open a connection to an LDAP server specified by `url`. This is an LDAP URL, from
    /// which the scheme (__ldap__, __ldaps__, or __ldapi__), host, and port are used. If
    /// the scheme is __ldapi__, only the host portion of the url is allowed, and it must
    /// be a percent-encoded path of a Unix domain socket.
    pub fn new(url: &str, handle: &Handle) -> io::Result<Self> {
        if !url.starts_with("ldapi://") {
            return LdapConnAsync::new_tcp(url, handle);
        }
        let path = url.split('/').nth(2).unwrap();
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "empty Unix domain socket path"));
        }
        if path.contains(':') {
            return Err(io::Error::new(io::ErrorKind::Other, "the port must be empty in the ldapi scheme"));
        }
        let dec_path = percent_decode(path.as_bytes()).decode_utf8_lossy();
        Ok(LdapConnAsync {
            in_progress: LdapWrapper::connect_unix(dec_path.borrow(), handle).shared(),
        })
    }

    fn new_tcp(url: &str, handle: &Handle) -> io::Result<Self> {
        let url = Url::parse(url).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        let mut port = 389;
        let scheme = match url.scheme() {
            s @ "ldap" => s,
            s @ "ldaps" => { port = 636; s },
            s => return Err(io::Error::new(io::ErrorKind::Other, format!("unimplemented LDAP URL scheme: {}", s))),
        };
        if let Some(url_port) = url.port() {
            port = url_port;
        }
        let host_port = match url.host_str() {
            Some(h) => format!("{}:{}", h, port),
            None => format!("localhost:{}", port),
        };
        let addr = match url.host() {
            Some(Host::Ipv4(v4)) if scheme == "ldap" => Some(SocketAddr::new(IpAddr::V4(v4), port)),
            Some(Host::Ipv6(v6)) if scheme == "ldap" => Some(SocketAddr::new(IpAddr::V6(v6), port)),
            Some(Host::Domain(_)) if scheme == "ldap" => {
                match host_port.to_socket_addrs() {
                    Ok(mut addrs) => match addrs.next() {
                        Some(addr) => Some(addr),
                        None => return Err(io::Error::new(io::ErrorKind::Other, format!("empty address list for: {}", host_port))),
                    },
                    Err(e) => return Err(e),
                }
            }
            _ => None,
        };
        Ok(LdapConnAsync {
            in_progress: match scheme {
                "ldap" => LdapWrapper::connect(&addr.expect("addr"), handle).shared(),
                "ldaps" => LdapWrapper::connect_ssl(&host_port, handle).shared(),
                _ => unimplemented!(),
            },
        })
    }
}

impl Future for LdapConnAsync {
    type Item = Ldap;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.in_progress.poll() {
            Ok(Async::Ready(ref wrapper)) => {
                let ldap = wrapper.ldap();
                Ok(Async::Ready(ldap))
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(ref e) => Err(io::Error::new(e.kind(), format!("{:?}", e))),
        }
    }
}
