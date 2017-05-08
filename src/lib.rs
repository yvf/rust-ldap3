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
//! documentation with a bolded __Note__, with a link to the GitHub issue discussing the
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
    pub use controls_impl::{Control, MakeCritical, PagedResults, RawControl, RelaxRules};
    pub use controls_impl::parse_control;
    pub use controls_impl::types::{self, ControlType};
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
