extern crate ldap3;
#[macro_use]
extern crate maplit;

use ldap3::{LdapConn, Mod};
use ldap3::controls::{MakeCritical, RelaxRules};

fn main() {
    let ldap = LdapConn::new("ldap://localhost:2389").expect("ldap handle");
    let (res, _ctrls) = ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret").expect("bind");
    if res.rc == 0 {
        let (res, _ctrls) = ldap
            .with_controls(vec![RelaxRules.critical().into()])
            .modify(
                "uid=inejge,ou=People,dc=example,dc=org",
                vec![
                    Mod::Delete("objectClass", hashset!{"account"}),
                    Mod::Add("objectClass", hashset!{"inetOrgPerson"}),
                    Mod::Add("sn", hashset!{"Nejgebauer"}),
                    Mod::Add("cn", hashset!{"Ivan Nejgebauer"}),
                ]
            ).expect("modify");
        println!("{:?}", res);
    }
}
