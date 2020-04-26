#[macro_use]
extern crate nom;
#[macro_use]
pub extern crate log;

pub type RequestId = i32;

pub mod asn1 {
    //! ASN.1 structure construction and parsing.
    //!
    //! This section is deliberately under-documented; it's expected that the ASN.1 subsystem will
    //! be extensively overhauled in the future. If you need examples of using the present interface
    //! for, e.g., implementing a new extended operation or a control, consult the source of existing
    //! exops/controls.
    pub use lber::common::TagClass;
    pub use lber::parse::{parse_tag, parse_uint};
    pub use lber::structure::{StructureTag, PL};
    pub use lber::structures::{
        ASNTag, Boolean, Enumerated, ExplicitTag, Integer, Null, OctetString, Sequence, Set, Tag,
    };
    pub use lber::universal::Types;
    pub use lber::write;
    pub use lber::IResult;
}
mod conn;
pub mod controls {
    //! Control construction and parsing.
    //!
    //! A control can be associated with a request or a response. Several common
    //! controls, such as [`PagedResults`](struct.PagedResults.html), are implemented
    //! directly by this library. If an implemented control has the same form for
    //! the request and the response, there will be a single structure for both.
    //! (This is the case for `PagedResults`.) If the response control is different,
    //! its name will consist of the request control name with the `Resp` suffix.
    //!
    //! A request control can be created by instantiating its structure and converting
    //! it to ASN.1 with `into()` when passing the instance or constructing the request
    //! control vector in the call to [`with_controls()`](../struct.LdapConn.html#method.with_controls).
    //! A third-party control must implement the conversion from an instance
    //! of itself to [`RawControl`](struct.RawControl.html), a general form of control.
    //!
    //! `RawControl`, together with an optional instance of [`ControlType`](types/index.html),
    //! forms the type [`Control`](struct.Control.html); a vector of `Control`s is part
    //! of the result of all LDAP operation which return one.
    //!
    //! The first element of `Control` will have a value if the parser recognizes
    //! the control's OID as one that is implemented by the library itself. Since the
    //! list of implemented controls is expected to grow, matching those values must
    //! be done through reexported types in the [`types`](types/index.html) module,
    //! and cannot be exhaustive.
    //!
    //! A recognized response control can be parsed by calling
    //! [`parse()`](struct.RawControl.html#method.parse) on the instance of `RawControl`
    //! representing it. A third-party control must implement the
    //! [`ControlParser`](trait.ControlParser.html) trait to support this interface.
    pub use crate::controls_impl::types;
    pub use crate::controls_impl::{Assertion, PagedResults, ProxyAuth, RelaxRules};
    pub use crate::controls_impl::{
        Control, ControlParser, CriticalControl, MakeCritical, RawControl,
    };
    pub use crate::controls_impl::{PostRead, PostReadResp, PreRead, PreReadResp, ReadEntryResp};
}
mod controls_impl;
mod exop_impl;
pub mod exop {
    //! Extended operation construction and parsing.
    //!
    //! A generic exop is represented by [`Exop`](struct.Exop.html). If a particular
    //! exop is implemented by this library, it may have one or two associated structs;
    //! one for constructing requests, and another for parsing responses. If request and
    //! response are the same, there is only the request struct; if they are different,
    //! the response struct's name will consist of the request struct name with the
    //! `Resp` suffix.
    //!
    //! A request struct must implement the `From` conversion of itself into `Exop`.
    //! A response struct must implement the [`ExopParser`](trait.ExopParser.html)
    //! trait.
    pub use crate::exop_impl::{Exop, ExopParser, WhoAmI, WhoAmIResp};
}
mod filter;
mod ldap;
mod protocol;
pub mod result;
mod search;
#[cfg(feature = "sync")]
mod sync;

pub use conn::{LdapConnAsync, LdapConnSettings};
pub use filter::parse as parse_filter;
pub use ldap::{Ldap, Mod};
pub use result::{LdapError, LdapResult};
pub use search::{Scope, SearchEntry, SearchStream};
#[cfg(feature = "sync")]
pub use sync::LdapConn;
pub use util::{dn_escape, ldap_escape};
