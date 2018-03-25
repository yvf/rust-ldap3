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
