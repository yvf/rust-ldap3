## v0.5.0, unreleased

* [breaking-change] Ldap::abandon() accepts the msgid, not id.
  It's not meant to be called directly any more.

* [breaking-change] SearchStream::id() has been removed.

* [breaking-change] LdapConn::abandon() has been removed.

* [breaking-change] LdapResult.rc is now u32 (was: u8).

* [breaking-change] Ldap::connect() and Ldap::connect_ssl() have an additional
  parameter, an optional connection timeout.

* Timeout support, which can be used both synchronously and asynchronously.
  Timeouts can be specified both for connection establishment and individual
  LDAP operations. For the first case, a connection must be constructed
  through LdapConnBuilder.

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
