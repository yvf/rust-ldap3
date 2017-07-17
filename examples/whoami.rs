extern crate ldap3;

use std::error::Error;

use ldap3::LdapConn;
use ldap3::exop::{ExopParser, WhoAmI, WhoAmIResp};

fn main() {
    match do_whoami() {
        Ok(_) => (),
        Err(e) => println!("{:?}", e),
    }
}

fn do_whoami() -> Result<(), Box<Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?.success()?;
    let (exop, _res) = ldap.extended(WhoAmI)?.success()?;
    if let Some(val) = exop.val {
        let whoami = WhoAmIResp::parse(val);
        println!("{}", whoami.authzid);
    }
    Ok(())
}
