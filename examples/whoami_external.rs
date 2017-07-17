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
    let ldap = LdapConn::new("ldapi://ldapi")?;
    ldap.sasl_external_bind()?.success()?;
    let (exop, _res) = ldap.extended(WhoAmI)?.success()?;
    if let Some(val) = exop.val {
        let whoami = WhoAmIResp::parse(val);
        println!("{}", whoami.authzid);
    }
    Ok(())
}
