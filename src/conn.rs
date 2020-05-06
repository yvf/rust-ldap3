use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(feature = "tls")]
use crate::exop_impl::StartTLS;
use crate::ldap::Ldap;
use crate::protocol::{ItemSender, LdapCodec, LdapOp, MaybeControls, ResultSender};
use crate::result::{LdapError, Result};
use crate::search::SearchItem;
use crate::RequestId;

use lber::structures::{Null, Tag};

#[cfg(feature = "tls")]
use futures_util::future::TryFutureExt;
use futures_util::sink::SinkExt;
#[cfg(feature = "tls")]
use native_tls::TlsConnector;
#[cfg(unix)]
use percent_encoding::percent_decode;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::stream::StreamExt;
use tokio::sync::mpsc;
#[cfg(feature = "tls")]
use tokio::sync::oneshot;
use tokio::time;
#[cfg(feature = "tls")]
use tokio_tls::{TlsConnector as TokioTlsConnector, TlsStream};
use tokio_util::codec::{Decoder, Framed};
use url::{self, Url};

#[derive(Debug)]
enum ConnType {
    Tcp(TcpStream),
    #[cfg(feature = "tls")]
    Tls(TlsStream<TcpStream>),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl AsyncRead for ConnType {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            ConnType::Tls(tls) => Pin::new(tls).poll_read(cx, buf),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnType {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            ConnType::Tls(tls) => Pin::new(tls).poll_write(cx, buf),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_flush(cx),
            #[cfg(feature = "tls")]
            ConnType::Tls(tls) => Pin::new(tls).poll_flush(cx),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            ConnType::Tls(tls) => Pin::new(tls).poll_shutdown(cx),
            #[cfg(unix)]
            ConnType::Unix(us) => Pin::new(us).poll_shutdown(cx),
        }
    }
}

/// Additional settings for an LDAP connection.
///
/// The structure is opaque for better extensibility. An instance with
/// default values is constructed by [`new()`](#method.new), and all
/// available settings can be replaced through a builder-like interface,
/// by calling the appropriate functions.
#[derive(Clone, Default)]
pub struct LdapConnSettings {
    conn_timeout: Option<Duration>,
    #[cfg(feature = "tls")]
    connector: Option<TlsConnector>,
    #[cfg(feature = "tls")]
    starttls: bool,
    #[cfg(feature = "tls")]
    no_tls_verify: bool,
}

impl LdapConnSettings {
    /// Create an instance of the structure with default settings.
    pub fn new() -> LdapConnSettings {
        LdapConnSettings {
            ..Default::default()
        }
    }

    /// Set the connection timeout. If a connetion to the server can't
    /// be established before the timeout expires, an error will be
    /// returned to the user. Defaults to `None`, meaning an infinite
    /// timeout.
    pub fn set_conn_timeout(mut self, timeout: Duration) -> Self {
        self.conn_timeout = Some(timeout);
        self
    }

    #[cfg(feature = "tls")]
    /// Set a custom TLS connector, which enables setting various options
    /// when establishing a secure connection. The default of `None` will
    /// use a connector with default settings.
    pub fn set_connector(mut self, connector: TlsConnector) -> Self {
        self.connector = Some(connector);
        self
    }

    #[cfg(feature = "tls")]
    /// If `true`, use the StartTLS extended operation to establish a
    /// secure connection. Defaults to `false`.
    pub fn set_starttls(mut self, starttls: bool) -> Self {
        self.starttls = starttls;
        self
    }

    #[cfg(feature = "tls")]
    /// The `starttls` settings indicates whether the StartTLS extended
    /// operation will be used to establish a secure connection.
    pub fn starttls(&self) -> bool {
        self.starttls
    }

    #[cfg(not(feature = "tls"))]
    /// Always `false` when no TLS support is compiled in.
    pub fn starttls(&self) -> bool {
        false
    }

    #[cfg(feature = "tls")]
    /// If `true`, try to establish a TLS connection without hostname
    /// verification. Defaults to `false`.
    pub fn set_no_tls_verify(mut self, no_tls_verify: bool) -> Self {
        self.no_tls_verify = no_tls_verify;
        self
    }
}

enum LoopMode {
    #[allow(dead_code)]
    SingleOp,
    Continuous,
}

#[allow(clippy::needless_doctest_main)]
/// Asynchronous connection to an LDAP server. __*__
///
/// In this version of the interface, opening a connection with [`new()`](#method.new)
/// will return a tuple consisting of the connection itself and a [`Ldap`](struct.Ldap.html)
/// handle for performing the LDAP operations. The connection must be spawned on the active
/// Tokio executor before using the handle. A convenience macro, [`drive!`](macro.drive.html), is
/// provided by the library. For the connection `conn`, it does the equivalent of:
///
/// ```rust,no_run
/// # use ldap3::LdapConnAsync;
/// # use log::warn;
/// # #[tokio::main]
/// # async fn main() {
/// # let (conn, _ldap) = LdapConnAsync::new("ldap://localhost:2389").await.unwrap();
/// tokio::spawn(async move {
///     if let Err(e) = conn.drive().await {
///         warn!("LDAP connection error: {}", e);
///     }
/// });
/// # }
/// ```
///
/// If you need custom connection lifecycle handling, use the [`drive()`](#method.drive) method
/// on the connection inside your own `async` block.
///
/// The `Ldap` handle can be freely cloned, with each clone capable of launching a separate
/// LDAP operation multiplexed on the original connection. Dropping the last handle will automatically
/// close the connection.
///
/// Some connections need additional parameters, but providing many separate functions to initialize
/// them, singly or in combination, would result in a cumbersome interface. Instead, connection
/// initialization is optimized for the expected most frequent usage, and additional customization
/// is possible through the [`LdapConnSettings`](struct.LdapConnSettings.html) struct, which can be
/// passed to [`with_settings()`](#method.with_settings).
pub struct LdapConnAsync {
    msgmap: Arc<Mutex<(i32, HashSet<i32>)>>,
    resultmap: HashMap<i32, ResultSender>,
    searchmap: HashMap<i32, ItemSender>,
    rx: mpsc::UnboundedReceiver<(RequestId, LdapOp, Tag, MaybeControls, ResultSender)>,
    id_scrub_rx: mpsc::UnboundedReceiver<RequestId>,
    stream: Framed<ConnType, LdapCodec>,
}

/// Drive the connection until its completion.
///
/// See the introduction of [LdapConnAsync](struct.LdapConnAsync.html) for the exact code produced by
/// the macro.
#[macro_export]
macro_rules! drive {
    ($conn:expr) => {
        tokio::spawn(async move {
            if let Err(e) = $conn.drive().await {
                $crate::log::warn!("LDAP connection error: {}", e);
            }
        });
    };
}

impl LdapConnAsync {
    /// Open a connection to an LDAP server specified by `url`, using
    /// `settings` to specify additional parameters.
    pub async fn with_settings(settings: LdapConnSettings, url: &str) -> Result<(Self, Ldap)> {
        if url.starts_with("ldapi://") {
            Ok(LdapConnAsync::new_unix(url, settings).await?)
        } else {
            // For some reason, "mut settings" is transformed to "__arg0" in the docs,
            // this is a workaround. On GitHub, at the time of writing, there is:
            //
            // https://github.com/rust-lang/docs.rs/issues/737
            //
            // But no issue in the Rust repo.
            let mut settings = settings;
            let timeout = settings.conn_timeout.take();
            let conn_future = LdapConnAsync::new_tcp(url, settings);
            Ok(if let Some(timeout) = timeout {
                time::timeout(timeout, conn_future).await?
            } else {
                conn_future.await
            }?)
        }
    }

    /// Open a connection to an LDAP server specified by `url`.
    ///
    /// The `url` is an LDAP URL. Depending on the platform and compile-time features, the
    /// library will recognize one or more URL schemes.
    ///
    /// The __ldap__ scheme, which uses a plain TCP connection, is always available. Unix-like
    /// platforms also support __ldapi__, using Unix domain sockets. With the __tls__ feature,
    /// the __ldaps__ scheme and StartTLS over __ldap__ are additionally supported.
    ///
    /// The connection element in the returned tuple must be spawned on the current Tokio
    /// executor before using the `Ldap` element. See the introduction to this struct's
    /// documentation.
    pub async fn new(url: &str) -> Result<(Self, Ldap)> {
        Self::with_settings(LdapConnSettings::new(), url).await
    }

    #[cfg(unix)]
    async fn new_unix(url: &str, _settings: LdapConnSettings) -> Result<(Self, Ldap)> {
        let path = url.split('/').nth(2).unwrap();
        if path.is_empty() {
            return Err(LdapError::EmptyUnixPath);
        }
        if path.contains(':') {
            return Err(LdapError::PortInUnixPath);
        }
        let dec_path = percent_decode(path.as_bytes()).decode_utf8_lossy();
        let stream = UnixStream::connect(dec_path.as_ref()).await?;
        Ok(Self::conn_pair(ConnType::Unix(stream)))
    }

    #[cfg(not(unix))]
    async fn new_unix(_url: &str, _settings: LdapConnSettings) -> Result<(Self, Ldap)> {
        unimplemented!("no Unix domain sockets on non-Unix platforms");
    }

    #[allow(unused_mut)]
    async fn new_tcp(url: &str, mut settings: LdapConnSettings) -> Result<(Self, Ldap)> {
        let url = Url::parse(url)?;
        let mut port = 389;
        let scheme = match url.scheme() {
            s @ "ldap" => {
                if settings.starttls() {
                    "starttls"
                } else {
                    s
                }
            }
            #[cfg(feature = "tls")]
            s @ "ldaps" => {
                settings = settings.set_starttls(false);
                port = 636;
                s
            }
            s => return Err(LdapError::UnknownScheme(String::from(s))),
        };
        if let Some(url_port) = url.port() {
            port = url_port;
        }
        let (_hostname, host_port) = match url.host_str() {
            Some(h) if h != "" => (h, format!("{}:{}", h, port)),
            Some(h) if h == "" => ("localhost", format!("localhost:{}", port)),
            _ => panic!("unexpected None from url.host_str()"),
        };
        let stream = TcpStream::connect(host_port.as_str()).await?;
        let (mut conn, mut ldap) = Self::conn_pair(ConnType::Tcp(stream));
        match scheme {
            "ldap" => (),
            #[cfg(feature = "tls")]
            s @ "ldaps" | s @ "starttls" => {
                let connector = match settings.connector {
                    Some(connector) => connector,
                    None => {
                        let mut builder = TlsConnector::builder();
                        if settings.no_tls_verify {
                            builder.danger_accept_invalid_certs(true);
                        }
                        builder.build().expect("connector")
                    }
                };
                if s == "starttls" {
                    let (tx, rx) = oneshot::channel();
                    tokio::spawn(async move {
                        conn.single_op(tx).await;
                    });
                    let res =
                        tokio::try_join!(rx.map_err(LdapError::from), ldap.extended(StartTLS));
                    match res {
                        Ok((conn_res, res)) => {
                            conn = conn_res?;
                            res.success()?;
                        }
                        Err(e) => return Err(e),
                    }
                }
                let parts = conn.stream.into_parts();
                let tls_stream = if let ConnType::Tcp(stream) = parts.io {
                    TokioTlsConnector::from(connector)
                        .connect(_hostname, stream)
                        .await?
                } else {
                    panic!("underlying stream not TCP");
                };
                conn.stream = parts.codec.framed(ConnType::Tls(tls_stream));
            }
            _ => unimplemented!(),
        }
        Ok((conn, ldap))
    }

    fn conn_pair(ctype: ConnType) -> (Self, Ldap) {
        let codec = LdapCodec;
        let (tx, rx) = mpsc::unbounded_channel();
        let (id_scrub_tx, id_scrub_rx) = mpsc::unbounded_channel();
        let conn = LdapConnAsync {
            msgmap: Arc::new(Mutex::new((0, HashSet::new()))),
            resultmap: HashMap::new(),
            searchmap: HashMap::new(),
            rx,
            id_scrub_rx,
            stream: codec.framed(ctype),
        };
        let ldap = Ldap {
            msgmap: conn.msgmap.clone(),
            tx,
            id_scrub_tx,
            last_id: 0,
            timeout: None,
            controls: None,
            search_opts: None,
        };
        (conn, ldap)
    }

    /// Repeatedly poll the connection until it exits.
    pub async fn drive(self) -> Result<()> {
        self.turn(LoopMode::Continuous).await.map(|_| ())
    }

    #[cfg(feature = "tls")]
    pub(crate) async fn single_op(self, tx: oneshot::Sender<Result<Self>>) {
        if tx.send(self.turn(LoopMode::SingleOp).await).is_err() {
            warn!("single op send error");
        }
    }

    async fn turn(mut self, mode: LoopMode) -> Result<Self> {
        loop {
            tokio::select! {
                req_id = self.id_scrub_rx.recv() => {
                    if let Some(req_id) = req_id {
                        self.resultmap.remove(&req_id);
                        self.searchmap.remove(&req_id);
                        let mut msgmap = self.msgmap.lock().expect("msgmap mutex (id_scrub)");
                        msgmap.1.remove(&req_id);
                    }
                },
                op_tuple = self.rx.recv() => {
                    if let Some((id, op, tag, controls, tx)) = op_tuple {
                        if let LdapOp::Search(ref search_tx) = op {
                            self.searchmap.insert(id, search_tx.clone());
                        }
                        if let Err(e) = self.stream.send((id, tag, controls)).await {
                            warn!("socket send error: {}", e);
                            return Err(LdapError::from(e));
                        } else {
                            match op {
                                LdapOp::Single => {
                                    self.resultmap.insert(id, tx);
                                    continue;
                                },
                                LdapOp::Search(_) => (),
                                LdapOp::Abandon(msgid) => {
                                    self.resultmap.remove(&msgid);
                                    self.searchmap.remove(&msgid);
                                    let mut msgmap = self.msgmap.lock().expect("msgmap mutex (abandon)");
                                    msgmap.1.remove(&id);
                                },
                                LdapOp::Unbind => {
                                    if let Err(e) = self.stream.close().await {
                                        warn!("socket shutdown error: {}", e);
                                        return Err(LdapError::from(e));
                                    }
                                },
                            }
                            if let Err(e) = tx.send((Tag::Null(Null { ..Default::default() }), vec![])) {
                                warn!("ldap null result send error: {:?}", e);
                            }
                        }
                    }
                },
                resp = self.stream.next() => {
                    let (id, (tag, controls)) = match resp {
                        None => break,
                        Some(Err(e)) => {
                            warn!("socket receive error: {}", e);
                            return Err(LdapError::from(e));
                        },
                        Some(Ok(resp)) => resp,
                    };
                    if let Some(tx) = self.searchmap.get(&id) {
                        let protoop = if let Tag::StructureTag(protoop) = tag {
                            protoop
                        } else {
                            panic!("unmatched tag structure: {:?}", tag);
                        };
                        let (item, mut remove) = match protoop.id {
                            4 | 25 => (SearchItem::Entry(protoop), false),
                            5 => (SearchItem::Done(Tag::StructureTag(protoop).into()), true),
                            19 => (SearchItem::Referral(protoop), false),
                            _ => panic!("unrecognized op id: {}", protoop.id),
                        };
                        if let Err(e) = tx.send((item, controls)) {
                            warn!("ldap search item send error, op={}: {:?}", id, e);
                            remove = true;
                        }
                        if remove {
                            self.searchmap.remove(&id);
                        }
                    } else if let Some(tx) = self.resultmap.remove(&id) {
                        if let Err(e) = tx.send((tag, controls)) {
                            warn!("ldap result send error: {:?}", e);
                        }
                        let mut msgmap = self.msgmap.lock().expect("msgmap mutex (stream rx)");
                        msgmap.1.remove(&id);
                    } else {
                        warn!("unmatched id: {}", id);
                    }
                },
            };
            if let LoopMode::SingleOp = mode {
                break;
            }
        }
        Ok(self)
    }
}
