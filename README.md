# LDAPv3 client library

A pure-Rust LDAP library using the Tokio stack.

The library can be used either synchronously or asynchronously. The aim is to
offer essentially the same call interface for both flavors, with the necessary
differences in interaction and return values according to the nature of I/O.

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies.ldap3]
version = "0.4.0"
```

Next, add this to your crate root (`src/lib.rs` or `src/main.rs`):

```rust
extern crate ldap3;
```

### Synchronous example

```rust
extern crate ldap3;

use ldap3::{LdapConn, Scope, SearchEntry};

fn main() {
    let ldap = LdapConn::new("ldap://ldap.example.org").expect("ldap conn");

    let (result_set, result, _controls) = ldap.search(
        "ou=People,dc=example,dc=org",
        Scope::Subtree,
        "objectClass=inetOrgPerson",
        vec!["uid"]
    ).expect("all results");

    println!("{:?}", result);
    for entry in result_set {
        println!("{:?}", SearchEntry::construct(entry));
    }
}
```

### Asynchronous example

```rust
extern crate futures;
extern crate ldap3;
extern crate tokio_core;

use std::io;

use futures::{Future, Stream};
use ldap::{LdapConnAsync, Scope, SearchEntry};
use tokio_core::reactor::Core;

fn main() {
    let mut core = Core::new().expect("core");
    let handle = core.handle();

    let ldap = LdapConnAsync::new("ldaps://ldap.example.org", &handle).expect("ldap conn");
    let srch = ldap
        .and_then(|ldap| {
            ldap.search(
                "ou=People,dc=example,dc=org",
                Scope::Subtree,
                "objectClass=inetOrgPerson",
                vec!["uid"])
        })
        .and_then(|(strm, rx)| {
            rx.map_err(|_e| io::Error::from(io::ErrorKind::Other))
                .join(strm.for_each(move |tag| {
                    println!("{:?}", SearchEntry::construct(tag));
                    Ok(())
                }))
        });

    let ((result, _controls), _) = core.run(srch).expect("op result");
    println!("{:?}", result);
}
```

## Status

All basic operations are implemented, as well as the support for request
and response controls. The driver should now be well equipped for the majority
of uses, albeit lacking the automated handling of several common scenarios,
such as referral chasing and paged results. Those two are high on the list
of development priorities.

TLS support exists for the case of immediate negotiation (aka __ldaps://__).
Caveat: certificate and hostname checking __can't be turned off__.

StartTLS will probably be supported in the medium term. Patches are welcome.

### Implemented operations

In order of appearance in the RFC:

- [x] Bind (simple)
- [x] Unbind [1]
- [x] Search
- [x] Modify
- [x] Add
- [x] Delete
- [x] ModifyDN
- [x] Compare
- [x] Abandon (incomplete)
- [ ] Extended

[1] Unbind doesn't close our side of the connection, since the underlying
TCP stream is inaccessible in the present implementation.

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
