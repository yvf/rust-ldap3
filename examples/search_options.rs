extern crate ldap3;

use ldap3::{LdapConn, Scope, SearchOptions, SearchEntry};

fn main() {
    let ldap = LdapConn::new("ldap://localhost:2389").expect("ldap handle");
    let (rs, res, _ctrls) = ldap
        .with_search_options(SearchOptions::new().sizelimit(1))
        .search(
            "ou=People,dc=example,dc=org",
            Scope::Subtree,
            "objectClass=inetOrgPerson",
            vec!["uid"]
    ).expect("search result");
    println!("Result: {:?}", res);
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
}
