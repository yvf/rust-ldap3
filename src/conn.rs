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
}

/// Handle for obtaining a stream of search results.
pub struct EntryStream {
    core: Rc<RefCell<Core>>,
    strm: Option<SearchStream>,
    rx_r: Option<oneshot::Receiver<(LdapResult, Vec<Control>)>>,
}

impl EntryStream {
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

    pub fn result(&mut self) -> io::Result<(LdapResult, Vec<Control>)> {
        if self.strm.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "cannot return result from an invalid stream"));
        }
        let rx_r = self.rx_r.take().expect("oneshot rx");
        let res = self.core.borrow_mut().run(rx_r).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        Ok(res)
    }

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
/// a handle which is used for all subsequent operations on that connection.
///
/// Most LDAP operations allow attaching a series of _controls_, which augment or modify
/// the operation. Controls are attached by calling [`with_controls()`](#method.with_controls)
/// on the handle, and using the result to call another modifier or the operation itself.
///
/// The Search operation has many parameters, most of which are infrequently used. Those
/// parameters can be specified by constructing a [`SearchOptions`](struct.SearchOptions.html)
/// structure and passing it to [`with_search_options()`](#method.with_serach_options)
/// called on the handle. This function can be combined with `with_controls()`, described above.
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
#[derive(Clone)]
pub struct LdapConn {
    core: Rc<RefCell<Core>>,
    inner: Ldap,
}

impl LdapConn {
    pub fn new(url: &str) -> io::Result<Self> {
        let mut core = Core::new()?;
        let conn = LdapConnAsync::new(url, &core.handle())?;
        let ldap = core.run(conn)?;
        Ok(LdapConn {
            core: Rc::new(RefCell::new(core)),
            inner: ldap,
        })
    }

    pub fn simple_bind(&self, bind_dn: &str, bind_pw: &str) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().simple_bind(bind_dn, bind_pw))?)
    }

    pub fn with_search_options(&self, opts: SearchOptions) -> &Self {
        self.inner.with_search_options(opts);
        self
    }

    pub fn with_controls(&self, ctrls: Vec<StructureTag>) -> &Self {
        self.inner.with_controls(ctrls);
        self
    }

    pub fn search<S: AsRef<str>>(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<S>) -> io::Result<(Vec<StructureTag>, LdapResult, Vec<Control>)> {
        let srch = self.inner.clone().search(base, scope, filter, attrs)
            .and_then(|(strm, rx_r)| {
                rx_r.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
                    .join(strm.collect())
            });
        let ((result, controls), result_set) = self.core.borrow_mut().run(srch)?;
        Ok((result_set, result, controls))
    }

    pub fn streaming_search<S: AsRef<str>>(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<S>) -> io::Result<EntryStream> {
        let (strm, rx_r) = self.core.borrow_mut().run(self.inner.clone().search(base, scope, filter, attrs))?;
        Ok(EntryStream { core: self.core.clone(), strm: Some(strm), rx_r: Some(rx_r) })
    }

    pub fn add<S: AsRef<str> + Eq + Hash>(&self, dn: &str, attrs: Vec<(S, HashSet<S>)>) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().add(dn, attrs))?)
    }

    pub fn delete(&self, dn: &str) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().delete(dn))?)
    }

    pub fn modify<S: AsRef<str> + Eq + Hash>(&self, dn: &str, mods: Vec<Mod<S>>) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().modify(dn, mods))?)
    }

    pub fn modifydn(&self, dn: &str, rdn: &str, delete_old: bool, new_sup: Option<&str>) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().modifydn(dn, rdn, delete_old, new_sup))?)
    }

    pub fn unbind(&self) -> io::Result<()> {
        Ok(self.core.borrow_mut().run(self.inner.clone().unbind())?)
    }

    pub fn compare<B: AsRef<[u8]>>(&self, dn: &str, attr: &str, val: B) -> io::Result<(LdapResult, Vec<Control>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().compare(dn, attr, val))?)
    }

    pub fn extended<E>(&self, exop: E) -> io::Result<(LdapResult, Exop, Vec<Control>)>
        where Vec<Tag>: From<E>
    {
        Ok(self.core.borrow_mut().run(self.inner.clone().extended(exop))?)
    }

    pub fn abandon(&self, id: RequestId) -> io::Result<()> {
        Ok(self.core.borrow_mut().run(self.inner.clone().abandon(id))?)
    }
}

/// Asynchronous handle for LDAP operations; analogue of `LdapConn`. __⁎__
#[derive(Clone)]
pub struct LdapConnAsync {
    in_progress: Shared<Box<Future<Item=LdapWrapper, Error=io::Error>>>,
}

impl LdapConnAsync {
    pub fn new(url: &str, handle: &Handle) -> io::Result<Self> {
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
