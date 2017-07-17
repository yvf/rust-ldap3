extern crate ldap3;

use std::error::Error;

use ldap3::LdapConn;
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
    ldap.sasl_external_bind()?.success()?;
    let (res, exop, _ctrls) = ldap.extended(WhoAmI)?;
    if res.rc == 0 {
        if let Some(val) = exop.val {
            let whoami: WhoAmIResp = parse_exop(val.as_ref());
            println!("{}", whoami.authzid);
        }
    }
    Ok(())
}
