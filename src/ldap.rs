use std::cell::RefCell;
use std::{io, mem};
use std::net::SocketAddr;
#[cfg(feature = "tls")]
use std::net::ToSocketAddrs;
#[cfg(unix)]
use std::path::Path;
use std::rc::Rc;

use lber::structure::StructureTag;
use lber::structures::Tag;
use futures::{future, Future};
use futures::sync::mpsc;
#[cfg(feature = "tls")]
use native_tls::TlsConnector;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;
use tokio_proto::TcpClient;
use tokio_proto::multiplex::ClientService;
use tokio_service::Service;
#[cfg(feature = "tls")]
use tokio_tls::proto::Client as TlsClient;
#[cfg(unix)]
use tokio_uds::UnixStream;
#[cfg(unix)]
use tokio_uds_proto::UnixClient;

use controls::Control;
use protocol::{LdapProto, ProtoBundle};
use search::{SearchItem, SearchOptions};

#[derive(Clone)]
enum ClientMap {
    Plain(ClientService<TcpStream, LdapProto>),
    #[cfg(feature = "tls")]
    Tls(ClientService<TcpStream, TlsClient<LdapProto>>),
    #[cfg(unix)]
    Unix(ClientService<UnixStream, LdapProto>),
}

#[derive(Clone)]
/// LDAP connection. __*__
///
/// This is a low-level structure representing an LDAP connection, which
/// provides methods returning futures of various LDAP operations. Inherent
/// methods for opening a connection themselves return futures which,
/// if successfully resolved, yield the structure instance. That instance
/// can be `clone()`d if the connection should be reused for multiple
/// operations.
///
/// All methods on an instance of this structure, except `with_*`, return
/// a future which must be polled inside some futures chain to obtain the
/// appropriate result. The synchronous interface provides methods with
/// exactly the same name and parameters, and identical semantics. Differences
/// in expected use are noted where they exist, such as the [`search()`]
/// (#method.search) method.
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
    ldap.next_search_options.borrow_mut().take();
    ldap.next_req_controls.borrow_mut().take()
}

pub enum LdapOp {
    Single(Tag, Option<Vec<StructureTag>>),
    Multi(Tag, mpsc::UnboundedSender<SearchItem>, Option<Vec<StructureTag>>),
    Solo(Tag, Option<Vec<StructureTag>>),
}

impl Ldap {
    /// Connect to an LDAP server without using TLS, using an IP address/port number
    /// in `addr`, and an event loop handle in `handle`.
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

    /// Connect to an LDAP server with an attempt to negotiate TLS immediately after
    /// establishing the TCP connection, using the host name and port number in `addr`,
    /// and an event loop handle in `handle`. The connection _must_ be by host name for
    /// TLS hostname check to work.
    #[cfg(feature = "tls")]
    pub fn connect_ssl(addr: &str, handle: &Handle) ->
            Box<Future<Item=Ldap, Error=io::Error>> {
        if addr.parse::<SocketAddr>().ok().is_some() {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "SSL connection must be by hostname")));
        }
        let sockaddr = addr.to_socket_addrs().unwrap_or_else(|_| vec![].into_iter()).next();
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

    /// Connect to an LDAP server through a Unix domain socket, using the path
    /// in `path`, and an event loop handle in `handle`.
    #[cfg(unix)]
    pub fn connect_unix<P: AsRef<Path>>(path: P, handle: &Handle) ->
            Box<Future<Item=Ldap, Error=io::Error>> {
        let proto = LdapProto::new(handle.clone());
        let bundle = proto.bundle();
        let client = UnixClient::new(proto)
            .connect(path, handle)
            .map(|client_proxy| {
                Ldap {
                    inner: ClientMap::Unix(client_proxy),
                    bundle: bundle,
                    next_search_options: Rc::new(RefCell::new(None)),
                    next_req_controls: Rc::new(RefCell::new(None)),
                }
            });
        Box::new(match client {
            Ok(ldap) => future::ok(ldap),
            Err(e) => future::err(e),
        })
    }

    /// See [`LdapConn::with_search_options()`](struct.LdapConn.html#method.with_search_options).
    pub fn with_search_options(&self, opts: SearchOptions) -> &Self {
        mem::replace(&mut *self.next_search_options.borrow_mut(), Some(opts));
        self
    }

    /// See [`LdapConn::with_controls()`](struct.LdapConn.html#method.with_controls).
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
            #[cfg(feature = "tls")]
            ClientMap::Tls(ref t) => Box::new(t.call(req)),
            #[cfg(unix)]
            ClientMap::Unix(ref u) => Box::new(u.call(req)),
        }
    }
}
