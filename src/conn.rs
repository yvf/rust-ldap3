use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use futures::{Async, Future, Poll};
use futures::future::Shared;
use tokio_core::reactor::Handle;
use url::{Host, Url};

use ldap::Ldap;

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

#[derive(Clone)]
pub struct LdapConn {
    in_progress: Shared<Box<Future<Item=LdapWrapper, Error=io::Error>>>,
}

impl LdapConn {
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
        Ok(LdapConn {
            in_progress: match scheme {
                "ldap" => LdapWrapper::connect(&addr.expect("addr"), &handle).shared(),
                "ldaps" => LdapWrapper::connect_ssl(&host_port, &handle).shared(),
                _ => unimplemented!(),
            },
        })
    }
}

impl Future for LdapConn {
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
