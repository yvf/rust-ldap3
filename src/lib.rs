//! A pure-Rust LDAP library using the Tokio stack.
//!
//! ## Usage
//!
//! In `Cargo.toml`:
//!
//! ```
//! [dependencies.ldap3]
//! version = "0.4"
//! ```
//!
//! In the crate root:
//!
//! ```
//! extern crate ldap3;
//! ```
//! ## Summary
//!
//! Although the library provides both synchronous and asynchronous interfaces,
//! presently the synchronous one is less likely to undergo breaking changes,
//! and is the preferred way to use the library. The [`LdapConn`](struct.LdapConn.html)
//! structure is the starting point for all synchronous operations. [`LdapConnAsync`]
//! (struct.LdapConnAsync) is its asynchronous analogue, and [`Ldap`](struct.Ldap) is
//! the low-level asynchronous connection handle used by both.
//!
//! In the [struct list](#structs), async-related structs have an asterisk (__*__) after
//! the short description.
//!
//! Since the library is still in development, none of the interfaces should be considered
//! stable. If a breaking change of some component is planned, it will be noted in the
//! documentation with a bolded __Note__, and a link to the GitHub issue discussing the
//! change, if applicable. General, crate-level issues with the documentation can be
//! discussed [here](https://github.com/inejge/ldap3/issues/3).
//!
//! The documentation is written for readers familiar with LDAP concepts and terminology,
//! which it won't attempt to explain.

extern crate bytes;
extern crate byteorder;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate lazy_static;
extern crate lber;
#[macro_use]
extern crate log;
extern crate native_tls;
#[macro_use]
extern crate nom;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_proto;
extern crate tokio_service;
extern crate tokio_tls;
#[cfg(unix)]
extern crate tokio_uds;
#[cfg(unix)]
extern crate tokio_uds_proto;
extern crate url;

mod abandon;
mod add;
mod bind;
mod compare;
mod conn;
pub mod controls {
    //! Control construction and parsing.
    //!
    //! A control can be associated with a request or a response. Several common
    //! controls, such as [`PagedResults`](struct.PagedResults.html), are implemented
    //! directly by this library. If an implemented control has the same form for
    //! the request and the response, there will be a single structure for both uses.
    //! (This is the case for `PagedResults`.) If the response control is different,
    //! its name will consist of the request control name with the `Resp` suffix.
    //!
    //! A request control can be created by instantiating its structure and converting
    //! it to ASN.1 with `into()` when constructing the request control vector in the
    //! call to [`with_controls()`](../struct.LdapConn.html#method.with_controls).
    //! Independently implemented controls must construct an instance of [`RawControl`]
    //! (struct.RawControl.html), a general form of control, and call `into()` on that
    //! instance.
    //!
    //! `RawControl`, together with an optional instance of [`ControlType`]
    //! (types/index.html), forms the type [`Control`](struct.Control.html); a vector
    //! of `Control`s is part of the result of all LDAP operation which return one.
    //!
    //! The first element of `Control` will have a value if the parser recognizes
    //! the control's OID as one that is implemented by the library itself. Since the
    //! list of implemented controls is expected to grow, matching those values must
    //! be done through reexported types in the [`types`](types/index.html) module,
    //! and cannot be exhaustive.
    //!
    //! A recognized response control can be parsed by [`parse_control()`](fn.parse_control.html).
    //! __Note__: this method will be removed in 0.5.x.
    // future text:
    // A recognized response control can be parsed by calling [`parse()`](struct.RawControl.html#method.parse)
    // on the instance of `RawControl` representing it.
    pub use controls_impl::{Control, MakeCritical, PagedResults, RawControl, RelaxRules};
    pub use controls_impl::parse_control;
    pub use controls_impl::types;
}
mod controls_impl;
mod delete;
mod extended;
mod exop_impl;
pub mod exop {
    //! Extended operation construction and parsing.
    pub use exop_impl::{Exop, WhoAmI, WhoAmIResp};
    pub use exop_impl::parse_exop;
}
mod filter;
mod ldap;
mod modify;
mod modifydn;
mod protocol;
mod search;
mod unbind;

pub use conn::{EntryStream, LdapConn, LdapConnAsync};
pub use ldap::Ldap;
pub use modify::Mod;
pub use protocol::LdapResult;
pub use search::{DerefAliases, Scope, SearchEntry, SearchOptions, SearchStream};

pub mod asn1 {
    //! ASN.1 structure construction and parsing.
    pub use lber::IResult;
    pub use lber::common::TagClass;
    pub use lber::structure::{PL, StructureTag};
    pub use lber::structures::{ASNTag, Boolean, Enumerated, ExplicitTag, Integer, Null, OctetString, Sequence, Set, Tag};
    pub use lber::parse::{parse_tag, parse_uint};
}
