extern crate ldap3;

use std::error::Error;

use ldap3::LdapConn;
use ldap3::controls::ProxyAuth;
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::exop::parse_exop;

fn main() {
    match do_whoami() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn do_whoami() -> Result<(), Box<Error>> {
    let ldap = LdapConn::new("ldapi://ldapi")?;
    ldap.simple_bind("cn=proxy,dc=example,dc=org", "topsecret")?.success()?;
    let (res, exop, _ctrls) = ldap
        .with_controls(vec![
            ProxyAuth {
                authzid: "dn:cn=proxieduser,dc=example,dc=org".to_owned()
            }.into()
        ])
        .extended(WhoAmI)?;
    if res.rc == 0 {
        if let Some(val) = exop.val {
            let whoami: WhoAmIResp = parse_exop(val.as_ref());
            println!("{}", whoami.authzid);
        }
    }
    Ok(())
}
