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
[changelog](CHANGELOG.md). The change of the search return type and inclusion of
response controls in the status struct are expected to result in most breakage,
although the impact will ultimately depend on the manner of using the API.

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

The two examples in the text perform exactly the same operation and should produce identical
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
scenarios, such as referral chasing and paged results.

TLS support exists for the case of immediate negotiation (aka __ldaps://__).
StartTLS will probably be supported in the medium term. On Unix-like systems,
connecting through a Unix domain socket with the __ldapi://__ scheme is
supported.

Caveats:

* Certificate and hostname checking __can't be turned off__ for TLS connections.

* Hostname resolution is synchronous. The library doesn't initiate any
  connections by itself, so this should be manageable in most scenarios.

* Unbind doesn't close our side of the connection, since the underlying
  TCP stream is inaccessible in the present implementation.

* Abandon can only terminate currently active streaming searches.

* Only version 3 of LDAP is supported.

* CLDAP (LDAP over UDP) is not supported.

## Upcoming changes

There are no firm plans for the next version. ASN.1 structures, internal parsing
and error handling all need improvement. StartTLS support would be nice to have.

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
