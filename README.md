# LDAP client library

A pure-Rust LDAP library using the Tokio stack.

### Attention!

The port to async/await and Tokio 0.2 is in progress. What you can see here
is a very early and very rough draft of the next version of the library.
Currently working are:

* Async connection and operations (TCP, TLS + StartTLS, Unix domain sockets).

* Simple Bind, SASL EXTERNAL Bind, streaming Search and Extended operations.

* Controls (not tested).

Not working:

* Synchronous connection/client.

* The rest of the operations.

* Automatic paging.

The remaining LDAP operations shouldn't be too difficult.  Synchronous operation
will come next. Automatic paging is not a priority.

Old examples have all been deleted to avoid confusion. As the code solidifies,
most of them will be ported back. There are three new examples, very much WIP.

The documentation is in disarray, and will be tackled once the interfaces
stabilize. Most of it exists in the previous version of the library, but will
have to be reworked according to the new layout of the code.

The library heavily depends on Tokio. Async-std support is not planned.

### Documentation

- [Version 0.6.x (old-stable)](https://docs.rs/ldap3/)

## Usage

The library can be used either synchronously or asynchronously. The aim is to
offer essentially the same call interface for both flavors, with the necessary
differences in interaction and return values according to the nature of I/O.

First, add this to your `Cargo.toml`:

```toml
[dependencies.ldap3]
version = "0.6"
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
and response controls. Automatic paged results are supported, but referral chasing
still isn't.

TLS support exists both for the case of immediate negotiation (aka __ldaps://__)
and StartTLS. On Unix-like systems, connecting through a Unix domain socket with the
__ldapi://__ scheme is supported.

Caveats:

* It may be impossible to completely turn off certificate and hostname checking
  for TLS connections. There is support for relaxing hostname checking and passing
  a custom `TlsConnector` when establishing a connection, but the specifics depend
  on the amount of customization available when creating a `TlsConnector`, which
  in turn depends on the platform TLS backend.

* Due to the structuring of support libraries, certificate errors may manifest
  themselves as a generic "broken pipe" error, and get triggered on first use of
  a connection, not on opening. To debug these kinds of issues, it's helpful
  to run the program while setting `RUST_LOG=tokio=trace` in the environment.
  See [this issue](https://github.com/inejge/ldap3/issues/14#issuecomment-323356983)
  for an example.

* Hostname resolution is synchronous by default. The resolver is configurable
  in the connection settings, so it's possible to plug in an async resolver
  running on the same event loop as the LDAP connection. The library still
  doesn't initiate any connections by itself, so setting a custom resolver
  shouldn't be necessary in most scenarios.

* Unbind doesn't close our side of the connection, since the underlying
  TCP stream is inaccessible in the present implementation.

* Abandon can only terminate currently active streaming searches.

* Only version 3 of LDAP is supported.

* CLDAP (LDAP over UDP) is not supported.

## Upcoming changes

The ability of a streaming Search to deal with the Sync protocol
([RFC 4533](https://tools.ietf.org/html/rfc4533)) will be developed in the 0.6
series. A similar mechanism may be usable for robust referral handling.

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
