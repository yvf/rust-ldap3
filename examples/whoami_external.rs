extern crate ldap3;

use ldap3::LdapConn;
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::exop::parse_exop;

fn main() {
    let ldap = LdapConn::new("ldapi://ldapi").expect("ldap handle");
    let (res, _ctrls) = ldap.sasl_external_bind().expect("bind");
    if res.rc == 0 {
        let (res, exop, _ctrls) = ldap.extended(WhoAmI).expect("extended");
        if res.rc == 0 {
            if let Some(val) = exop.val {
                let whoami: WhoAmIResp = parse_exop(val.as_ref());
                println!("{}", whoami.authzid);
            }
        }
    }
}
