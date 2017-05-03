extern crate ldap3;

use ldap3::{LdapConn, Scope, SearchEntry};

fn main() {
    let ldap = LdapConn::new("ldap://localhost:2389").expect("ldap handle");
    let (rs, res, _ctrls) = ldap.search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "(&(objectClass=locality)(l=ma*))",
        vec!["l"]
    ).expect("search result");
    println!("Result: {:?}", res);
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
}
