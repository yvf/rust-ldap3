use std::cell::RefCell;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::rc::Rc;

use asnom::structures::Tag;
use futures::{future, Future};
use futures::sync::oneshot;
use native_tls::TlsConnector;
use tokio_core::reactor::Handle;
use tokio_proto::TcpClient;
use tokio_proto::streaming::{Body, Message};
use tokio_proto::streaming::multiplex::RequestId;
use tokio_proto::util::client_proxy::ClientProxy;
use tokio_service::Service;
use tokio_tls::proto::Client as TlsClient;

use protocol::{LdapProto, Exchanges};

pub type RequestMessage = Message<LdapOp, Body<(), io::Error>>;
pub type ResponseMessage = Message<Tag, Body<Tag, io::Error>>;

struct ClientMap(ClientProxy<RequestMessage, ResponseMessage, io::Error>);

pub struct Ldap {
    inner: ClientMap,
    exchanges: Rc<RefCell<Exchanges>>,
    handle: Handle,
}

pub enum LdapOp {
    Single(Tag),
    Streaming(Tag, oneshot::Sender<RequestId>),
    Cancel(RequestId, Tag),
}

pub fn ldap_handle(ldap: &Ldap) -> Handle {
    ldap.handle.clone()
}

pub fn ldap_exchanges(ldap: &Ldap) -> Rc<RefCell<Exchanges>> {
    ldap.exchanges.clone()
}

impl Ldap {
    pub fn connect(addr: &SocketAddr, handle: &Handle) ->
        Box<Future<Item = Ldap, Error = io::Error>> {
        let proto = LdapProto::new();
        let exchanges = proto.exchanges();
        let loop_handle = handle.clone();
        let ret = TcpClient::new(proto)
            .connect(addr, handle)
            .map(|client_proxy| {
                Ldap {
                    inner: ClientMap(client_proxy),
                    exchanges: exchanges,
                    handle: loop_handle,
                }
            });
        Box::new(ret)
    }

    pub fn connect_ssl(addr: &str, handle: &Handle) ->
        Box<Future<Item = Ldap, Error = io::Error>> {
        if addr.parse::<SocketAddr>().ok().is_some() {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "SSL connection must be by hostname")));
        }
        let sockaddr = addr.to_socket_addrs().unwrap_or(vec![].into_iter()).next();
        if sockaddr.is_none() {
            return Box::new(future::err(io::Error::new(io::ErrorKind::Other, "no addresses found")));
        }
        let proto = LdapProto::new();
        let exchanges = proto.exchanges();
        let loop_handle = handle.clone();
        let wrapper = TlsClient::new(proto,
            TlsConnector::builder().expect("tls_builder").build().expect("connector"),
            addr.split(':').next().expect("hostname"));
        let ret = TcpClient::new(wrapper)
            .connect(&sockaddr.unwrap(), handle)
            .map(|client_proxy| {
                Ldap {
                    inner: ClientMap(client_proxy),
                    exchanges: exchanges,
                    handle: loop_handle,
                }
            });
        Box::new(ret)
    }
}

impl Service for Ldap {
    type Request = LdapOp;
    type Response = ResponseMessage;
    type Error = io::Error;
    type Future = Box<Future<Item=ResponseMessage, Error=io::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        self.inner.call(req)
    }
}

impl Service for ClientMap {
    type Request = LdapOp;
    type Response = ResponseMessage;
    type Error = io::Error;
    type Future = Box<Future<Item=ResponseMessage, Error=io::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        Box::new(self.0.call(Message::WithoutBody(req)))
    }
}
