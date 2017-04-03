use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

use asnom::structures::Tag;
use futures::{future, Future};
use native_tls::TlsConnector;
use tokio_core::reactor::Handle;
use tokio_proto::util::client_proxy::ClientProxy;
use tokio_proto::TcpClient;
use tokio_service::Service;
use tokio_tls::proto::Client as TlsClient;

use protocol::LdapProto;
use service::{LdapMessage, TokioMessage};

struct ClientMap(ClientProxy<TokioMessage, TokioMessage, io::Error>);

pub struct Ldap {
    inner: ClientMap,
}

impl Ldap {
    pub fn connect(addr: &SocketAddr, handle: &Handle) ->
        Box<Future<Item = Ldap, Error = io::Error>> {
        let ret = TcpClient::new(LdapProto)
            .connect(addr, handle)
            .map(|client_proxy| {
                Ldap { inner: ClientMap(client_proxy) }
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
        let wrapper = TlsClient::new(LdapProto,
            TlsConnector::builder().expect("tls_builder").build().expect("connector"),
            addr.split(':').next().expect("hostname"));
        let ret = TcpClient::new(wrapper)
            .connect(&sockaddr.unwrap(), handle)
            .map(|client_proxy| {
                Ldap { inner: ClientMap(client_proxy) }
            });
        Box::new(ret)
    }
}

impl Service for Ldap {
    type Request = Tag;
    type Response = LdapMessage;
    type Error = io::Error;
    type Future = Box<Future<Item = LdapMessage, Error = io::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        self.inner.call(LdapMessage::Once(req))
    }
}

impl Service for ClientMap {
    type Request = LdapMessage;
    type Response = LdapMessage;
    type Error = io::Error;
    type Future = Box<Future<Item=LdapMessage, Error=io::Error>>;

    fn call(&self, req: LdapMessage) -> Self::Future {
        Box::new(self.0.call(req.into()).map(LdapMessage::from))
    }
}
