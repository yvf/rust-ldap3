extern crate ldap3;

use ldap3::{LdapConn, Scope};

const ENTRIES_BEFORE_ABANDON: usize = 20;

fn main() {
    let ldap = LdapConn::new("ldap://localhost:2389").expect("ldap handle");
    let mut count = 0;
    let mut strm = ldap.streaming_search(
        "ou=Places,dc=example,dc=org",
        Scope::Subtree,
        "objectClass=locality",
        vec!["l"]
    ).expect("stream");
    while let Ok(Some(_r)) = strm.next() {
        count += 1;
        if count == ENTRIES_BEFORE_ABANDON {
            ldap.abandon(strm.id().expect("id")).expect("abandon");
            continue;
        }
    }
    let (res, _ctrls) = strm.result().expect("result");
    println!("Result: {:?}", res);
}
