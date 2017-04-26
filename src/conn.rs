use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use futures::{Async, Future, Poll};
use futures::future::Shared;
use tokio_core::reactor::{Core, Handle};
use url::{Host, Url};

use asnom::structure::StructureTag;
use ldap::Ldap;
use protocol::LdapResult;

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

pub struct LdapConn {
    core: Core,
    inner: Ldap,
}

impl LdapConn {
    pub fn new(url: &str) -> io::Result<Self> {
        let mut core = Core::new()?;
        let conn = LdapConnAsync::new(url, &core.handle())?;
        let ldap = core.run(conn)?;
        Ok(LdapConn {
            core: core,
            inner: ldap,
        })
    }

    pub fn simple_bind(&mut self, bind_dn: &str, bind_pw: &str) -> io::Result<(LdapResult, Option<StructureTag>)> {
        Ok(self.core.run(self.inner.clone().simple_bind(bind_dn, bind_pw))?)
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
