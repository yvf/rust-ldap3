## v0.8.3, 2021-01-05

* Fix id/value splitting in extension parsing,
  limiting the number of elements to at most 2.
  (The bug can be worked around by percent-encoding
  the equals sign.)

## v0.8.2, 2020-12-30

* Two new connection establishment functions
  accept an url::Url reference instead of &str.
  They exist to avoid re-parsing the URL if its
  parameters were extracted earlier.

* LDAP URL parsing added. The syntax specified by
  RFC 4516 is mapped into the LdapUrlParams struct.
  An LDAP URL must be parsed by url::Url::parse()
  before extracting its components.

* Matched Values control support added.

## v0.8.1/v0.7.2, 2020-11-24

* Timeouts are honored in Search operations
  ([#63](https://github.com/inejge/ldap3/issues/63)).

* Password Modify extended operation support added
  ([#60](https://github.com/inejge/ldap3/issues/60)).

## v0.8.0, 2020-10-19

Port to Tokio 0.3 and the refresh of a couple of
dependencies. Otherwise, there are no functional
differences compared to 0.7.1.

## v0.7.1, 2020-06-11

This version completely overhauls the internals of the
library by porting it to Tokio 0.2 and async/await. This
makes the asynchronous interface one big breaking change,
so it makes no sense to enumerate the differences. The
synchronous interface proved rather more stable, but there
are a couple of breaking changes there, too.

* Rustls can be used as an alternative to `native-tls` for
  TLS support.

* The search adapter framework lets user-supplied code control
  the execution of a Search operation and transform returned
  entries and result codes. Two adapters are included in the
  crate: EntriesOnly, which filters out referrals and
  intermediate messages from the stream, and PagedResults,
  which uses the control of the same name and automatically
  applies it to a Search operation until the full result set
  is retrieved.

* [breaking change]: `ResultEntry` now has public components,
  where the second is the set of controls associated with the
  entry. This is necessary in order to process all elements of
  the content synchronization protocol. The struct is marked
  as non-exhaustive to help ensure forward compatibility.

* [breaking change]: The `LdapConn` struct now must be mutable,
  since all methods require `&mut self`.

* [breaking change]: The error part of the functions and methods
  that return `Result` is now an instance of `LdapError`. There is
  a blanket automatic conversion to `io::Error` to make the change
  less problematic for applications.

* [breaking change]: Streaming Search returns raw entries, without
  trying to parse referrals or intermediate messages. The
  EntriesOnly search adapter can be used to restore the earlier
  behavior. Ordinary Search drops intermediate messages and collects
  all referrals in the result vector.

* [breaking change]: There is no `autopage` search option for
  automatically applying the Paged Results control to a Search.
  Use the PagedResults search adapter instead.

* `LdapConn` is now `Send`, meaning that it's usable in connection
  pool managers such as `r2d2`.

## v0.6.1, 2018-10-16

* A number of dependencies have been updated to avoid
  deprecation warnings when compiling.

* Skipping all TLS checks is simplified, being abstracted
  by native-tls.

* TLS connections can be made to an IP address.

## v0.6.0, 2018-03-25

* Searches can be automatically paged by using
  `SearchOptions::autopage()`.

* `LdapConnSettings::set_no_tls_verify()` can be used to
  request skipping certificate hostname checks. If supported
  by the platform TLS backend, this may be combined with a
  custom connector which can skip all TLS checks.

* SASL EXTERNAL binds also work when authenticating with TLS
  client certificates, so `Ldap::sasl_external_bind()` and its
  sync adapter are no longer limited to Unix-like systems.

* It's possible to set a custom hostname resolver with
  `LdapConnSettings::set_resolver()`. The intent is to enable
  asynchronous resolution when dealing with async connections.

* [breaking change] `Ldap::{connect,connect_ssl,connect_unix}`
  signatures have changed to accept an `LdapConnSettings` argument.

* [breaking change] `Ldap::connect_ssl()` is additionally changed
  to accept the hostname for TLS checks instead of finding it out
  itself. This is done to centralize address resolution.

* [breaking change] `LdapConnBuilder` has been removed. Connection
  parameters can now be set via `LdapConnSettings` and passed to
  connection establishment routines via `with_settings()`, both
  sync and async.

* StartTLS is now supported.

* Add and Modify operations now accept arbitrary binary attribute
  values ([#20](https://github.com/inejge/ldap3/issues/20)).

## v0.5.1, 2017-08-21

* An LDAP connection can be constructed with a pre-built TLS connector
  using `LdapConnBuilder::with_tls_connector()`
  ([#11](https://github.com/inejge/ldap3/pull/11)). This function is not
  publicly documented, to avoid fixing the API. The intent is to allow
  connections which need additional connector configuration, such as
  those to a server using a self-signed certificate.

* The function `ldap3::dn_escape()` is provided to escape RDN values
  when constructing a DN ([#13](https://github.com/inejge/ldap3/pull/13)).

## v0.5.0, 2017-07-20

Changes are listed approximately in reverse chronological order. Since they
are so numerous for this release, and many are breaking changes, please
read them carefully.

* Assertion, Pre- and Post-Read controls are implemented in-tree.

* `Ldap::with_controls()` can also accept a single control, without the
  need to construct a vector.

* [breaking change] Searches return a vector of `ResultEntry` elements, so
  the internal ASN.1 type is hidden. This changes the signature of
  `SearchEntry::construct()`.

* Control and exop implementations don't depend on internal traits and
  structs, enabling independent third-party development.

* [breaking change] Exop and control handling is streamlined, but old parsing
  methods don't work any more. The signatures of `Ldap::extended()`,
  `LdapConn::extended()`, `Ldap::with_controls()` and `LdapConn::with_controls()`
  have changed.

* `LdapResult` implements `success()`, which returns the structure itself if
   `rc` is zero, or an error if it's not. There's also `non_error()`, which
   also considers the value 10 (referral) as successful.

* [breaking change] Compare returns `CompareResult`, a newtype of `LdapResult`
  which implements the `equals()` method, transforming compareFalse/compareTrue
  rc values to a boolean.

* [breaking change] Non-streaming search returns a wrapper type, `SearchResult`.
  The `success()` method can be invoked on a value of this type, destructuring
  it to an anonymous tuple of a entry vector and result struct, and propagating
  error cases, as determined by `LdapResult.rc`, upward.

* [breaking change] Async and sync search APIs are now aligned. `Ldap::search()`
  returns a future of the result entry vector, which it internally collects; what
  used to be `Ldap::search()` is now named `Ldap::streaming_search()`.

* [breaking change] `Ldap::streaming_search()` returns a future of just a SearchStream,
  instead of a tuple. The result receiver must be extracted from the stream
  instance with `SearchStream::get_result_rx()`. The receiver is also simplified,
  and now retrieves just the `LdapResult`.

* [breaking change] `LdapResult` contains the response controls.

* [breaking change] `Ldap::abandon()` accepts the msgid, not id.
  It's not meant to be called directly any more.

* [breaking change] `SearchStream::id()` has been removed.

* [breaking change] `LdapConn::abandon()` has been removed.

* [breaking change] `LdapResult.rc` is now `u32` (was: `u8`).

* [breaking change] `Ldap::connect()` and `Ldap::connect_ssl()` have an additional
  parameter, an optional connection timeout.

* Timeout support, which can be used both synchronously and asynchronously.
  Timeouts can be specified both for connection establishment and individual
  LDAP operations. For the first case, a connection must be constructed
  through LdapConnBuilder.

* The function `ldap3::ldap_escape()` is provided to escape search literals when
  constructing a search filter.

## v0.4.4, 2017-05-29

* Fix Windows build ([#7](https://github.com/inejge/ldap3/pull/7)).

* Make TLS support optional ([#6](https://github.com/inejge/ldap3/pull/6)).

* Reorganize build-time features: "tls" includes TLS support, and is on
  by default, while "minimal" excludes both TLS and Unix domain sockets.

## v0.4.3, 2017-05-12

* Documentation for controls and extended operations.

* Minimal documentation for the ASN.1 subsystem.

* Proxy Authorization control has been implemented.

## v0.4.2, 2017-05-08

* Documentation update.

* Support for Unix domain sockets on Unix-like systems.

* Support for SASL EXTERNAL binds, also limited to Unix-like systems
  for the time being, since they can only work on Unix domain socket
  connections (we can't use TLS client certs yet.)

## v0.4.1, 2017-05-06

* Fix integer parsing ([#1](https://github.com/inejge/ldap3/issues/1)).
  Active Directory length encoding triggered this bug.

* Fix the crash when parsing binary attributes ([#2](https://github.com/inejge/ldap3/issues/2)).
  The `SearchEntry`
  struct now has an additional field `bin_attrs`, containing all attributes
  which had at least one value that couldn't be converted into a `String`.
  Since it's possible that otherwise unconstrained binary attributes have
  values that _can_ be successfully converted into `String`s in a particular
  result set, the presence of such attributes should be checked for both
  in `attrs` and in `bin_attrs`.

  This is technically a breaking change, but since it isn't expected that
  any `SearchEntry` instance would've been created manually, the version
  stays at 0.4.x.

## v0.4.0, 2017-05-03

First published version.
