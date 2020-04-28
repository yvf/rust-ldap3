# LDAP client library

A pure-Rust LDAP library using the Tokio stack.

### Attention!

The library has recently been ported to Tokio 0.2 and async/await. For previous
users of the synchronous API, there is one major change to be aware of:

__The conection handle, `LdapConn`, must be mutable.__

All methods on `LdapConn` now take `&mut self`. Another big change is that
every error return in the library now uses instances of `LdapError`, but since
there is automatic conversion to `io::Error`, this shouldn't be too noticeable
in the applications.

The synchronous API is otherwise almost exactly the same. Most visible
differences are in the asynchronous API, which is, with the introduction of
async/await, much more pleasant to use. The internal restructuring has also
made some aspects of library more robust and the implementation closer to
the specification.

Old examples have all been deleted to avoid confusion. As the code solidifies,
most of them will be ported back. The documentation has been adapted to the
new code layout.

### Documentation

- [Version 0.7.0-alpha (current)](https://docs.rs/ldap3/0.7.0-alpha.3/ldap3/)

- [Version 0.6.x (old-stable)](https://docs.rs/ldap3/0.6.1/ldap3/)

## Usage

The library can be used either synchronously or asynchronously. The aim is to
offer essentially the same call interface for both flavors, with the necessary
differences in interaction and return values according to the nature of I/O.

Add this to your `Cargo.toml`:

```toml
[dependencies.ldap3]
version = "0.7.0-alpha"
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

## License

Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
