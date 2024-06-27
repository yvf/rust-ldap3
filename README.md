# LDAP client library

A pure-Rust LDAP client library using the Tokio stack.

### Version notices

The 0.11 branch is now in maintenance mode, and 0.10 is retired. If you're
using GSSAPI and compiling with Rust 1.78.0 or later, upgrade to 0.11.5.

### Documentation

API reference:

- [Version 0.11.x](https://docs.rs/ldap3/0.11.5/ldap3/)

There is an [LDAP introduction](https://github.com/inejge/ldap3/blob/27a247c8a6e4e2c86f664f4280c4c6499f0e9fe5/LDAP-primer.md)
for those still getting their bearings in the LDAP world.

### Miscellaneous notes

The library is client-only. One cannot make an LDAP server or a proxy with it.
It supports only version 3 of the protocol over connection-oriented transports.

There is no built-in support for connection pooling, automatic fallback or
reconnections.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies.ldap3]
version = "0.11.5"
```

The library can be used either synchronously or asynchronously. The aim is to
offer essentially the same call interface for both flavors, with the necessary
differences in interaction and return values according to the nature of I/O.

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

* __gssapi__ (disabled by default): Kerberos/GSSAPI support. On Windows, system support
  crates and SDK libraries are used. Elsewhere, the feature needs Clang and its development
  libraries (for `bindgen`), as well as the Kerberos development libraries. On Debian/Ubuntu,
  that means `clang-N`, `libclang-N-dev` and `libkrb5-dev`. It should be clear from these
  requirements that GSSAPI support uses FFI to C libraries; you should consider the security
  implications of this fact.

  For usage notes and caveats, see the documentation for `Ldap::sasl_gssapi_bind()` in
  the API reference.

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
