extern crate ldap3;

use std::time::Duration;
use ldap3::{LdapConn, LdapConnBuilder, Scope, SearchEntry};

fn main() {
    let ldap = LdapConnBuilder::<LdapConn>::new()
        .with_conn_timeout(Duration::from_secs(5))
        .connect("ldap://localhost:2389")
        .expect("ldap handle");
    let (rs, res) = ldap
        .with_timeout(Duration::from_secs(5))
        .search(
            "ou=Places,dc=example,dc=org",
            Scope::Subtree,
            "(&(objectClass=locality)(l=man*))",
            vec!["l"]
        ).expect("search result");
    println!("Result: {:?}", res);
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
}
