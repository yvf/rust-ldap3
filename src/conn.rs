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
use url::{Host, Url};

use asnom::structure::StructureTag;
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

pub struct EntryStream {
    core: Rc<RefCell<Core>>,
    strm: Option<SearchStream>,
    rx_r: Option<oneshot::Receiver<(LdapResult, Option<StructureTag>)>>,
}

impl EntryStream {
    pub fn next(&mut self) -> io::Result<Option<StructureTag>> {
        let strm = self.strm.take();
        if strm.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "cannot fetch from an invalid stream"));
        }
        let (tag, strm) = self.core.borrow_mut().run(strm.expect("stream").into_future()).map_err(|e| e.0)?;
        self.strm = Some(strm);
        Ok(tag)
    }

    pub fn result(&mut self) -> io::Result<(LdapResult, Option<StructureTag>)> {
        if self.strm.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "cannot return result from an invalid stream"));
        }
        let rx_r = self.rx_r.take().expect("oneshot rx");
        let res = self.core.borrow_mut().run(rx_r).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))?;
        Ok(res)
    }
}

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

    pub fn simple_bind(&self, bind_dn: &str, bind_pw: &str) -> io::Result<(LdapResult, Option<StructureTag>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().simple_bind(bind_dn, bind_pw))?)
    }

    pub fn with_search_options(&self, opts: SearchOptions) -> &Self {
        self.inner.with_search_options(opts);
        self
    }

    pub fn search(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<&str>) -> io::Result<(Vec<StructureTag>, LdapResult, Option<StructureTag>)> {
        let srch = self.inner.clone().search(base, scope, filter, attrs)
            .and_then(|(strm, rx_r)| {
                rx_r.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
                    .join(strm.collect())
            });
        let ((result, controls), result_set) = self.core.borrow_mut().run(srch)?;
        Ok((result_set, result, controls))
    }

    pub fn streaming_search(&self, base: &str, scope: Scope, filter: &str, attrs: Vec<&str>) -> io::Result<EntryStream> {
        let (strm, rx_r) = self.core.borrow_mut().run(self.inner.clone().search(base, scope, filter, attrs))?;
        Ok(EntryStream { core: self.core.clone(), strm: Some(strm), rx_r: Some(rx_r) })
    }

    pub fn add<S: AsRef<str> + Eq + Hash>(&self, dn: S, attrs: Vec<(S, HashSet<S>)>) -> io::Result<(LdapResult, Option<StructureTag>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().add(dn, attrs))?)
    }

    pub fn delete<S: AsRef<str>>(&self, dn: S) -> io::Result<(LdapResult, Option<StructureTag>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().delete(dn))?)
    }

    pub fn modify<S: AsRef<str> + Eq + Hash>(&self, dn: S, mods: Vec<Mod<S>>) -> io::Result<(LdapResult, Option<StructureTag>)> {
        Ok(self.core.borrow_mut().run(self.inner.clone().modify(dn, mods))?)
    }
}

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
                "ldap" => LdapWrapper::connect(&addr.expect("addr"), &handle).shared(),
                "ldaps" => LdapWrapper::connect_ssl(&host_port, &handle).shared(),
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
                return Ok(Async::Ready(ldap));
            },
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(ref e) => return Err(io::Error::new(e.kind(), format!("{:?}", e))),
        }
    }
}
