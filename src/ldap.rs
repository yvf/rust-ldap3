use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::controls_impl::IntoRawControlVec;
use crate::exop::Exop;
use crate::exop_impl::{construct_exop, StartTLS};
use crate::protocol::{ItemSender, LdapCodec, LdapOp, MaybeControls, ResultSender};
use crate::result::{ExopResult, LdapResult};
use crate::search::{SearchItem, SearchOptions, SearchStream};
use crate::RequestId;

use lber::common::TagClass;
use lber::parse::parse_uint;
use lber::structures::{Integer, Null, OctetString, Sequence, Tag};
use lber::universal::Types;
use lber::IResult;

use futures_util::future::TryFutureExt;
use futures_util::sink::SinkExt;
use log::warn;
#[cfg(feature = "tls")]
use native_tls::TlsConnector;
use percent_encoding::percent_decode;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio::stream::StreamExt;
use tokio::sync::{mpsc, oneshot};
use tokio::time;
#[cfg(feature = "tls")]
use tokio_tls::{TlsConnector as TokioTlsConnector, TlsStream};
use tokio_util::codec::{Decoder, Framed};
use url::{self, Url};

pub type Result<T> = std::result::Result<T, LdapError>;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("empty Unix domain socket path")]
    EmptyUnixPath,
    #[error("the port must be empty in the ldapi scheme")]
    PortInUnixPath,
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("op send error: {source}")]
    OpSend {
        #[from]
        source: mpsc::error::SendError<(RequestId, LdapOp, Tag, MaybeControls, ResultSender)>,
    },
    #[error("result recv error: {source}")]
    ResultRecv {
        #[from]
        source: oneshot::error::RecvError,
    },
    #[error("timeout: {elapsed}")]
    Timeout {
        #[from]
        elapsed: time::Elapsed,
    },
    #[error("filter parse error")]
    FilterParsing,
    #[error("premature end of search stream")]
    EndOfStream,
    #[error("url parse error: {source}")]
    UrlParsing {
        #[from]
        source: url::ParseError,
    },
    #[error("unknown LDAP URL scheme: {0}")]
    UnknownScheme(String),
    #[error("native TLS error: {source}")]
    NativeTLS {
        #[from]
        source: native_tls::Error,
    },
}

impl From<LdapError> for io::Error {
    fn from(le: LdapError) -> io::Error {
        match le {
            LdapError::Io { source, .. } => source,
            _ => io::Error::new(io::ErrorKind::Other, format!("{}", le)),
        }
    }
}

#[derive(Debug)]
pub struct Ldap {
    pub(crate) msgmap: Arc<Mutex<(i32, HashSet<i32>)>>,
    pub(crate) tx: mpsc::UnboundedSender<(RequestId, LdapOp, Tag, MaybeControls, ResultSender)>,
    pub(crate) last_id: i32,
    pub(crate) timeout: Option<Duration>,
    pub(crate) controls: MaybeControls,
    pub(crate) search_opts: Option<SearchOptions>,
}

impl Clone for Ldap {
    fn clone(&self) -> Self {
        Ldap {
            msgmap: self.msgmap.clone(),
            tx: self.tx.clone(),
            last_id: 0,
            timeout: None,
            controls: None,
            search_opts: None,
        }
    }
}

#[derive(Debug)]
enum ConnType {
    Tcp(TcpStream),
    #[cfg(feature = "tls")]
    Tls(TlsStream<TcpStream>),
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
            ConnType::Unix(us) => Pin::new(us).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_flush(cx),
            #[cfg(feature = "tls")]
            ConnType::Tls(tls) => Pin::new(tls).poll_flush(cx),
            ConnType::Unix(us) => Pin::new(us).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ConnType::Tcp(ts) => Pin::new(ts).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            ConnType::Tls(tls) => Pin::new(tls).poll_shutdown(cx),
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
    /// when establishing a secure connection. See the documentation for
    /// [native_tls](https://docs.rs/native-tls/0.1.4/native_tls/).
    /// Defaults to `None`, which will use a connector with default
    /// settings.
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
    ///
    /// The connection can still fail if the server certificate is
    /// considered invalid for other reasons (e.g., chain of trust or
    /// expiration date.) Depending on the platform, using a
    /// custom connector with backend-specific options _and_ setting
    /// this option to `true` may enable connections to servers with
    /// invalid certificates. One tested combination is OpenSSL with
    /// a connector for which `SSL_VERIFY_NONE` has been set.
    pub fn set_no_tls_verify(mut self, no_tls_verify: bool) -> Self {
        self.no_tls_verify = no_tls_verify;
        self
    }
}

enum LoopMode {
    SingleOp,
    Continuous,
}

pub struct LdapConnAsync {
    msgmap: Arc<Mutex<(i32, HashSet<i32>)>>,
    resultmap: HashMap<i32, ResultSender>,
    searchmap: HashMap<i32, ItemSender>,
    rx: mpsc::UnboundedReceiver<(RequestId, LdapOp, Tag, MaybeControls, ResultSender)>,
    stream: Framed<ConnType, LdapCodec>,
}

impl LdapConnAsync {
    pub async fn with_settings(settings: LdapConnSettings, url: &str) -> Result<(Self, Ldap)> {
        if url.starts_with("ldapi://") {
            Ok(LdapConnAsync::new_unix(url, settings).await?)
        } else {
            Ok(LdapConnAsync::new_tcp(url, settings).await?)
        }
    }

    pub async fn new(url: &str) -> Result<(Self, Ldap)> {
        if url.starts_with("ldapi://") {
            Ok(LdapConnAsync::new_unix(url, LdapConnSettings::new()).await?)
        } else {
            Ok(LdapConnAsync::new_tcp(url, LdapConnSettings::new()).await?)
        }
    }

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
                    let res = tokio::try_join!(
                        rx.map_err(|e| LdapError::from(e)),
                        ldap.extended(StartTLS)
                    );
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
        let conn = LdapConnAsync {
            msgmap: Arc::new(Mutex::new((0, HashSet::new()))),
            resultmap: HashMap::new(),
            searchmap: HashMap::new(),
            rx: rx,
            stream: codec.framed(ctype),
        };
        let ldap = Ldap {
            msgmap: conn.msgmap.clone(),
            tx: tx,
            last_id: 0,
            timeout: None,
            controls: None,
            search_opts: None,
        };
        (conn, ldap)
    }

    pub async fn drive(self) -> Result<()> {
        self.turn(LoopMode::Continuous).await.map(|_| ())
    }

    pub(crate) async fn single_op(self, tx: oneshot::Sender<Result<Self>>) {
        if let Err(_) = tx.send(self.turn(LoopMode::SingleOp).await) {
            warn!("single op send error");
        }
    }

    async fn turn(mut self, mode: LoopMode) -> Result<Self> {
        loop {
            tokio::select! {
                op_tuple = self.rx.recv() => {
                    if let Some((id, op, tag, controls, tx)) = op_tuple {
                        if let &LdapOp::Search(ref search_tx) = &op {
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
                                    let mut msgmap = self.msgmap.lock().expect("msgmap mutex (abandon)");
                                    msgmap.1.remove(&id);
                                    self.resultmap.remove(&msgid);
                                    self.searchmap.remove(&msgid);
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
                            5 => (SearchItem::Done(Tag::StructureTag(protoop).into(), controls), true),
                            19 => (SearchItem::Referral(protoop), false),
                            _ => panic!("unrecognized op id: {}", protoop.id),
                        };
                        if let Err(e) = tx.send(item) {
                            warn!("ldap search item send error, op={}: {:?}", id, e);
                            remove = true;
                        }
                        if remove {
                            self.searchmap.remove(&id);
                        }
                    } else if let Some(tx) = self.resultmap.remove(&id) {
                        let mut msgmap = self.msgmap.lock().expect("msgmap mutex (stream rx)");
                        msgmap.1.remove(&id);
                        if let Err(e) = tx.send((tag, controls)) {
                            warn!("ldap result send error: {:?}", e);
                        }
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

impl Ldap {
    fn next_msgid(&mut self) -> i32 {
        let mut msgmap = self.msgmap.lock().expect("msgmap mutex (inc id)");
        let last_ldap_id = msgmap.0;
        let mut next_ldap_id = last_ldap_id;
        loop {
            if next_ldap_id == std::i32::MAX {
                next_ldap_id = 1;
            } else {
                next_ldap_id += 1;
            }
            if !msgmap.1.contains(&next_ldap_id) {
                break;
            }
            assert_ne!(
                next_ldap_id, last_ldap_id,
                "LDAP message id wraparound with no free slots"
            );
        }
        msgmap.0 = next_ldap_id;
        msgmap.1.insert(next_ldap_id);
        next_ldap_id
    }

    pub(crate) async fn op_call(&mut self, op: LdapOp, req: Tag) -> Result<(LdapResult, Exop)> {
        let id = self.next_msgid();
        self.last_id = id;
        let (tx, rx) = oneshot::channel();
        self.tx.send((id, op, req, self.controls.take(), tx))?;
        let response = if let Some(timeout) = self.timeout.take() {
            time::timeout(timeout, rx).await?
        } else {
            rx.await
        }?;
        let (ldap_ext, controls) = (LdapResultExt::from(response.0), response.1);
        let (mut result, exop) = (ldap_ext.0, ldap_ext.1);
        result.ctrls = controls;
        Ok((result, exop))
    }

    pub fn last_id(&mut self) -> RequestId {
        self.last_id
    }

    /// See [`LdapConn::with_search_options()`](struct.LdapConn.html#method.with_search_options).
    pub fn with_search_options(&mut self, opts: SearchOptions) -> &mut Self {
        self.search_opts = Some(opts);
        self
    }

    /// See [`LdapConn::with_controls()`](struct.LdapConn.html#method.with_controls).
    pub fn with_controls<V: IntoRawControlVec>(&mut self, ctrls: V) -> &mut Self {
        self.controls = Some(ctrls.into());
        self
    }

    /// See [`LdapConn::with_timeout()`](struct.LdapConn.html#method.with_timeout).
    pub fn with_timeout(&mut self, duration: Duration) -> &mut Self {
        self.timeout = Some(duration);
        self
    }

    /// See [`LdapConn::simple_bind()`](struct.LdapConn.html#method.simple_bind).
    pub async fn simple_bind(&mut self, bind_dn: &str, bind_pw: &str) -> Result<LdapResult> {
        let req = Tag::Sequence(Sequence {
            id: 0,
            class: TagClass::Application,
            inner: vec![
                Tag::Integer(Integer {
                    inner: 3,
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: Vec::from(bind_dn),
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    id: 0,
                    class: TagClass::Context,
                    inner: Vec::from(bind_pw),
                }),
            ],
        });
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// See [`LdapConn::sasl_external_bind()`](struct.LdapConn.html#method.sasl_external_bind).
    pub async fn sasl_external_bind(&mut self) -> Result<LdapResult> {
        let req = Tag::Sequence(Sequence {
            id: 0,
            class: TagClass::Application,
            inner: vec![
                Tag::Integer(Integer {
                    inner: 3,
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: Vec::new(),
                    ..Default::default()
                }),
                Tag::Sequence(Sequence {
                    id: 3,
                    class: TagClass::Context,
                    inner: vec![
                        Tag::OctetString(OctetString {
                            inner: Vec::from("EXTERNAL"),
                            ..Default::default()
                        }),
                        Tag::OctetString(OctetString {
                            inner: Vec::new(),
                            ..Default::default()
                        }),
                    ],
                }),
            ],
        });
        Ok(self.op_call(LdapOp::Single, req).await?.0)
    }

    /// See [`LdapConn::extended()`](struct.LdapConn.html#method.extended).
    pub async fn extended<E>(&mut self, exop: E) -> Result<ExopResult>
    where
        E: Into<Exop>,
    {
        let req = Tag::Sequence(Sequence {
            id: 23,
            class: TagClass::Application,
            inner: construct_exop(exop.into()),
        });

        self.op_call(LdapOp::Single, req)
            .await
            .map(|et| ExopResult(et.1, et.0))
    }

    pub fn into_search_stream(self) -> SearchStream {
        SearchStream::new(self)
    }
}

#[derive(Clone, Debug)]
pub struct LdapResultExt(pub LdapResult, pub Exop);

impl From<Tag> for LdapResultExt {
    fn from(t: Tag) -> LdapResultExt {
        let t = match t {
            Tag::StructureTag(t) => t,
            Tag::Null(_) => {
                return LdapResultExt(
                    LdapResult {
                        rc: 0,
                        matched: String::from(""),
                        text: String::from(""),
                        refs: vec![],
                        ctrls: vec![],
                    },
                    Exop {
                        name: None,
                        val: None,
                    },
                )
            }
            _ => unimplemented!(),
        };
        let mut tags = t.expect_constructed().expect("result sequence").into_iter();
        let rc = match parse_uint(
            tags.next()
                .expect("element")
                .match_class(TagClass::Universal)
                .and_then(|t| t.match_id(Types::Enumerated as u64))
                .and_then(|t| t.expect_primitive())
                .expect("result code")
                .as_slice(),
        ) {
            IResult::Done(_, rc) => rc as u32,
            _ => panic!("failed to parse result code"),
        };
        let matched = String::from_utf8(
            tags.next()
                .expect("element")
                .expect_primitive()
                .expect("octet string"),
        )
        .expect("matched dn");
        let text = String::from_utf8(
            tags.next()
                .expect("element")
                .expect_primitive()
                .expect("octet string"),
        )
        .expect("diagnostic message");
        let mut refs = Vec::new();
        let mut exop_name = None;
        let mut exop_val = None;
        loop {
            match tags.next() {
                None => break,
                Some(comp) => match comp.id {
                    3 => {
                        let raw_refs = match comp.expect_constructed() {
                            Some(rr) => rr,
                            None => panic!("failed to parse referrals"),
                        };
                        refs.push(
                            raw_refs
                                .into_iter()
                                .map(|t| t.expect_primitive().expect("octet string"))
                                .map(String::from_utf8)
                                .map(|s| s.expect("uri"))
                                .collect(),
                        );
                    }
                    10 => {
                        exop_name = Some(
                            String::from_utf8(comp.expect_primitive().expect("octet string"))
                                .expect("exop name"),
                        );
                    }
                    11 => {
                        exop_val = Some(comp.expect_primitive().expect("octet string"));
                    }
                    _ => (),
                },
            }
        }
        LdapResultExt(
            LdapResult {
                rc: rc,
                matched: matched,
                text: text,
                refs: refs,
                ctrls: vec![],
            },
            Exop {
                name: exop_name,
                val: exop_val,
            },
        )
    }
}
