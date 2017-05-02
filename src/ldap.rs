use std::cell::RefCell;
use std::{io, mem};
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
use tokio_proto::multiplex::ClientService;
use tokio_service::Service;
use tokio_tls::proto::Client as TlsClient;

use controls::Control;
use protocol::{LdapProto, ProtoBundle};
use search::{SearchItem, SearchOptions};

#[derive(Clone)]
enum ClientMap {
    Plain(ClientService<TcpStream, LdapProto>),
    Tls(ClientService<TcpStream, TlsClient<LdapProto>>),
}

#[derive(Clone)]
/// LDAP connection. __⁎__
pub struct Ldap {
    inner: ClientMap,
    bundle: Rc<RefCell<ProtoBundle>>,
    next_search_options: Rc<RefCell<Option<SearchOptions>>>,
    next_req_controls: Rc<RefCell<Option<Vec<StructureTag>>>>,
}

pub fn bundle(ldap: &Ldap) -> Rc<RefCell<ProtoBundle>> {
    ldap.bundle.clone()
}

pub fn next_search_options(ldap: &Ldap) -> Option<SearchOptions> {
    ldap.next_search_options.borrow_mut().take()
}

pub fn next_req_controls(ldap: &Ldap) -> Option<Vec<StructureTag>> {
    ldap.next_req_controls.borrow_mut().take()
}

pub enum LdapOp {
    Single(Tag, Option<Vec<StructureTag>>),
    Multi(Tag, mpsc::UnboundedSender<SearchItem>, Option<Vec<StructureTag>>),
    Solo(Tag, Option<Vec<StructureTag>>),
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
                    next_search_options: Rc::new(RefCell::new(None)),
                    next_req_controls: Rc::new(RefCell::new(None)),
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
                    next_search_options: Rc::new(RefCell::new(None)),
                    next_req_controls: Rc::new(RefCell::new(None)),
                }
            });
        Box::new(ret)
    }

    pub fn with_search_options(&self, opts: SearchOptions) -> &Self {
        mem::replace(&mut *self.next_search_options.borrow_mut(), Some(opts));
        self
    }

    pub fn with_controls(&self, ctrls: Vec<StructureTag>) -> &Self {
        mem::replace(&mut *self.next_req_controls.borrow_mut(), Some(ctrls));
        self
    }
}

impl Service for Ldap {
    type Request = LdapOp;
    type Response = (Tag, Vec<Control>);
    type Error = io::Error;
    type Future = Box<Future<Item=Self::Response, Error=io::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        self.inner.call(req)
    }
}

impl Service for ClientMap {
    type Request = LdapOp;
    type Response = (Tag, Vec<Control>);
    type Error = io::Error;
    type Future = Box<Future<Item=Self::Response, Error=io::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        match *self {
            ClientMap::Plain(ref p) => Box::new(p.call(req)),
            ClientMap::Tls(ref t) => Box::new(t.call(req)),
        }
    }
}
