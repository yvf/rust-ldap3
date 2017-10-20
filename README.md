# LDAP client library

A pure-Rust LDAP library using the Tokio stack.

The library can be used either synchronously or asynchronously. The aim is to
offer essentially the same call interface for both flavors, with the necessary
differences in interaction and return values according to the nature of I/O.

### Documentation

- [Version 0.5.x (current)](https://docs.rs/ldap3/)
- [Version 0.4.4](https://docs.rs/ldap3/0.4.4/ldap3/)

### Attention!

Version 0.5 has a large number of breaking changes, which are described in the
[changelog](https://github.com/inejge/ldap3/blob/4f4a9f07062b1cf90703b2b38c17770394318626/CHANGELOG.md).
The change of the search return type and inclusion of response controls in the
status struct are expected to result in most breakage, although the impact will
ultimately depend on the manner of using the API. For a good illustration of the
fixes needed in real-life code, see [this patch](https://github.com/lawliet89/rowdy/pull/57/files#diff-958ef05f8d9516354027128727e6e8ef).

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies.ldap3]
version = "0.5"
```

Next, add this to your crate root (`src/lib.rs` or `src/main.rs`):

```rust
extern crate ldap3;
```

## Examples

The following two examples perform exactly the same operation and should produce identical
results. They should be run against the example server in the `data` subdirectory of the crate source.
Other sample programs expecting the same server setup can be found in the `examples` subdirectory.

### Synchronous search

```rust
extern crate ldap3;

use std::error::Error;

use ldap3::{LdapConn, Scope, SearchEntry};

fn main() {
    match do_search() {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    }
}

fn do_search() -> Result<(), Box<Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    let (rs, _res) = ldap.search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "(&(objectClass=locality)(l=ma*))",
        vec!["l"]
    )?.success()?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(())
}
```

### Asynchronous search

```rust
extern crate futures;
extern crate ldap3;
extern crate tokio_core;

use std::error::Error;

use futures::Future;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use tokio_core::reactor::Core;

fn main() {
    match do_search() {
        Ok(_) => (),
        Err(e) => println!("{}", e),
    }
}

fn do_search() -> Result<(), Box<Error>> {
    let mut core = Core::new()?;
    let handle = core.handle();
    let ldap = LdapConnAsync::new("ldap://localhost:2389", &handle)?;
    let srch = ldap.and_then(|ldap|
        ldap.search(
            "ou=Places,dc=example,dc=org",
            Scope::Subtree,
            "(&(objectClass=locality)(l=ma*))",
            vec!["l"]
        ))
        .and_then(|response| response.success())
        .and_then(|(rs, _res)| Ok(rs));
    let rs = core.run(srch)?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(())
}
```

## Status

All LDAP protocol operations are implemented, as well as the support for request
and response controls. The driver still lacks automated handling of several common
scenarios, such as referral chasing and paged results, although the latter is
availabale in the latest master.

TLS support exists for the case of immediate negotiation (aka __ldaps://__).
StartTLS is also supported in the latest master, but see the changelog for
the list of breaking changes which might need accounting for in your code.
On Unix-like systems, connecting through a Unix domain socket with the
__ldapi://__ scheme is supported.

Caveats:

* Certificate and hostname checking __can't be turned off__ for TLS connections.
  This may not be strictly true for the latest master, since there's support for
  relaxing hostname checking and passing a custom `TlsConnector` when establishing
  a connection. The specifics depend on the amount of customization available when
  creating a `TlsConnector`, which in turn depends on the platform TLS backend.

* Due to the structuring of support libraries, certificate errors may manifest
  themselves as a generic "broken pipe" error, and get triggered on first use of
  a connection, not on opening. To debug these kinds of issues, it's helpful
  to run the program while setting `RUST_LOG=tokio=trace` in the environment.
  See [this issue](https://github.com/inejge/ldap3/issues/14#issuecomment-323356983)
  for an example.

* Hostname resolution is synchronous by default. The latest master makes the
  resolver configurable in the connection settings, so it's possible to plug in
  an async resolver running on the same event loop as the LDAP connection.
  The library still doesn't initiate any connections by itself, so setting
  a custom resolver shouldn't be necessary in most scenarios.

* Unbind doesn't close our side of the connection, since the underlying
  TCP stream is inaccessible in the present implementation.

* Abandon can only terminate currently active streaming searches.

* Only version 3 of LDAP is supported.

* CLDAP (LDAP over UDP) is not supported.

## Upcoming changes

There are no firm plans for the next version. ASN.1 structures, internal parsing
and error handling all need improvement. StartTLS support would be nice to have.

## Compatibility notes

The earliest stable compiler which is routinely tested to build the crate is 1.15.1.
The hard lower limit is 1.13, which introduced the '?' operator, used extensively
throughout the source.

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
