extern crate ldap3;
extern crate native_tls;
extern crate env_logger;

use std::error::Error;

use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use native_tls::TlsConnector;

fn main() {
    drop(env_logger::init());
    match do_tls_conn() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn custom_connector() -> Result<TlsConnector, Box<Error>> {
    let mut builder = TlsConnector::builder();
    builder.danger_accept_invalid_certs(true);
    Ok(builder.build()?)
}

#[cfg(any(not(unix), target_os = "macos"))]
fn custom_connector() -> Result<TlsConnector, Box<Error>> {
    Ok(TlsConnector::builder()?.build()?)
}

fn do_tls_conn() -> Result<(), Box<Error>> {
    let settings = LdapConnSettings::new()
        .set_no_tls_verify(true)
        .set_connector(custom_connector()?);
    let ldap = LdapConn::with_settings(settings, "ldaps://127.0.0.1")?;
    let (rs, _) = ldap.search(
        "",
        Scope::Base,
        "objectClass=*",
        vec!["+"]
    )?.success()?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(())
}
