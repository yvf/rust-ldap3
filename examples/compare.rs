extern crate ldap3;

use ldap3::LdapConn;

fn main() {
    let ldap = LdapConn::new("ldap://localhost:2389").expect("ldap handle");
    let (res, _ctrls) = ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret").expect("bind");
    if res.rc == 0 {
        let (res, _ctrls) = ldap.compare(
            "uid=inejge,ou=People,dc=example,dc=org",
            "userPassword",
            "doublesecret"
        ).expect("compare");
        println!("{:?}", res);
    }
}
