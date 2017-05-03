extern crate ldap3;
#[macro_use]
extern crate maplit;

use ldap3::LdapConn;

fn main() {
    let ldap = LdapConn::new("ldap://localhost:2389").expect("ldap handle");
    let (res, _ctrls) = ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret").expect("bind");
    if res.rc == 0 {
        let (res, _ctrls) = ldap.add(
            "uid=extra,ou=People,dc=example,dc=org",
            vec![
                ("objectClass", hashset!{"inetOrgPerson"}),
                ("uid", hashset!{"extra"}),
                ("cn", hashset!{"Extra User"}),
                ("sn", hashset!{"User"}),
            ]
        ).expect("add");
        println!("{:?}", res);
    }
}
