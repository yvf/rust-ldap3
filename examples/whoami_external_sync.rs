// Demonstrates:
//
// 1. SASL EXTERNAL bind;
// 2. "Who Am I?" Extended operation.

use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::result::Result;
use ldap3::LdapConn;

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldapi://ldapi")?;
    let _res = ldap.sasl_external_bind()?.success()?;
    let (exop, _res) = ldap.extended(WhoAmI)?.success()?;
    let whoami: WhoAmIResp = exop.parse();
    println!("{}", whoami.authzid);
    Ok(())
}
