use std::io;
use std::net::SocketAddr;

use futures::{Async, Future, Poll};
use futures::future::Shared;
use tokio_core::reactor::Handle;

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
}

#[derive(Clone)]
pub struct LdapConn {
    in_progress: Shared<Box<Future<Item=LdapWrapper, Error=io::Error>>>,
    _uri: String,
}

impl LdapConn {
    pub fn new(uri: &str, handle: &Handle) -> Self {
        let addr = "127.0.0.1:2389".parse().unwrap();
        LdapConn {
            in_progress: LdapWrapper::connect(&addr, &handle).shared(),
            _uri: uri.to_owned(),
        }
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
