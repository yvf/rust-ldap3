# LDAP client library

A pure-Rust LDAP library using the Tokio stack.

### Attention!

The library has recently been ported to Tokio 0.2 and async/await. For previous
users of the synchronous API, there are two changes to be aware of:

1. __The connection handle, `LdapConn`, must be mutable.__ All methods on `LdapConn`
   now take `&mut self`.

2. Every error return in the library now uses instances of `LdapError`. Since
   there is an automatic conversion to `io::Error`, this shouldn't be too noticeable
   in the applications.

The synchronous API is otherwise almost exactly the same. Most visible
differences are in the asynchronous API, which is, with the introduction of
async/await, much more pleasant to use. The internal restructuring has also
made some aspects of the library more robust and the implementation closer to
the specification.

### Documentation

- [Version 0.7.x (current)](https://docs.rs/ldap3/0.7.1/ldap3/)

- [Version 0.6.x (old-stable)](https://docs.rs/ldap3/0.6.1/ldap3/)

### Note

The library is client-only. One cannot make an LDAP server or a proxy with it.

## Usage

The library can be used either synchronously or asynchronously. The aim is to
offer essentially the same call interface for both flavors, with the necessary
differences in interaction and return values according to the nature of I/O.

Add this to your `Cargo.toml`:

```toml
[dependencies.ldap3]
version = "0.7"
```

## Examples

The following two examples perform exactly the same operation and should produce identical
results. They should be run against the example server in the `data` subdirectory of the crate source.
Other sample programs expecting the same server setup can be found in the `examples` subdirectory.

### Synchronous search

```rust
use ldap3::{LdapConn, Scope, SearchEntry};
use ldap3::result::Result;

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:2389")?;
    let (rs, _res) = ldap.search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "(&(objectClass=locality)(l=ma*))",
        vec!["l"]
    )?.success()?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(ldap.unbind()?)
}
```

### Asynchronous search

```rust
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use ldap3::result::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:2389").await?;
    ldap3::drive!(conn);
    let (rs, _res) = ldap.search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "(&(objectClass=locality)(l=ma*))",
        vec!["l"]
    ).await?.success()?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(ldap.unbind().await?)
}
```

## Compile-time features

The following features are available at compile time:

* __sync__ (enabled by default): Synchronous API support.

* __tls__ (enabled by default): TLS support, backed by the `native-tls` crate, which uses
 a platform-specific TLS backend. This is an alias for __tls-native__.

* __tls-rustls__ (disabled by default): TLS support, backed by the Rustls library.

Without any features, only plain TCP connections (and Unix domain sockets on Unix-like
platforms) are available. For TLS support, __tls__ and __tls-rustls__ are mutually
exclusive: choosing both will produce a compile-time error.

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
