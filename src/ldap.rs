use std::cell::RefCell;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::rc::Rc;

use asnom::structure::StructureTag;
use asnom::structures::Tag;
use futures::{future, Future};
use futures::sync::mpsc;
use native_tls::TlsConnector;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;
use tokio_proto::TcpClient;
use tokio_proto::multiplex::{ClientService, RequestId};
use tokio_service::Service;
use tokio_tls::proto::Client as TlsClient;

use protocol::{LdapProto, ProtoBundle};

enum ClientMap {
    Plain(ClientService<TcpStream, LdapProto>),
    Tls(ClientService<TcpStream, TlsClient<LdapProto>>),
}

pub struct Ldap {
    inner: ClientMap,
    bundle: Rc<RefCell<ProtoBundle>>,
}

pub fn bundle(ldap: &Ldap) -> Rc<RefCell<ProtoBundle>> {
    ldap.bundle.clone()
}

pub enum LdapOp {
    Single(Tag),
    Multi(Tag, mpsc::UnboundedSender<(Tag, Option<StructureTag>)>),
    Cancel(Tag, RequestId),
}

impl Ldap {
    pub fn connect(addr: &SocketAddr, handle: &Handle) ->
        Box<Future<Item=Ldap, Error=io::Error>> {
        let proto = LdapProto::new(handle.clone());
        let bundle = proto.bundle();
        let ret = TcpClient::new(proto)
            .connect(addr, handle)
            .map(|client_proxy| {
                Ldap {
                    inner: ClientMap::Plain(client_proxy),
                    bundle: bundle,
                }
            });
        Box::new(ret)
    }

    pub fn connect_ssl(addr: &str, handle: &Handle) ->
        Box<Future<Item=Ldap, Error=io::Error>> {
        if addr.parse::<SocketAddr>().ok().is_some() {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "SSL connection must be by hostname")));
        }
        let sockaddr = addr.to_socket_addrs().unwrap_or(vec![].into_iter()).next();
        if sockaddr.is_none() {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "no addresses found")));
        }
        let proto = LdapProto::new(handle.clone());
        let bundle = proto.bundle();
        let wrapper = TlsClient::new(proto,
            TlsConnector::builder().expect("tls_builder").build().expect("connector"),
            addr.split(':').next().expect("hostname"));
        let ret = TcpClient::new(wrapper)
            .connect(&sockaddr.unwrap(), handle)
            .map(|client_proxy| {
                Ldap {
                    inner: ClientMap::Tls(client_proxy),
                    bundle: bundle,
                }
            });
        Box::new(ret)
    }
}

impl Service for Ldap {
    type Request = LdapOp;
    type Response = (Tag, Option<StructureTag>);
    type Error = io::Error;
    type Future = Box<Future<Item=Self::Response, Error=io::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        self.inner.call(req)
    }
}

impl Service for ClientMap {
    type Request = LdapOp;
    type Response = (Tag, Option<StructureTag>);
    type Error = io::Error;
    type Future = Box<Future<Item=Self::Response, Error=io::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        match *self {
            ClientMap::Plain(ref p) => Box::new(p.call(req)),
            ClientMap::Tls(ref t) => Box::new(t.call(req)),
        }
    }
}
