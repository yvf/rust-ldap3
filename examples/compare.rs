extern crate ldap3;

use std::error::Error;

use ldap3::LdapConn;

fn main() {
    match do_compare() {
        Ok(eq) => println!("{}equal", if eq { "" } else { "not " }),
        Err(e) => println!("{:?}", e),
    }
}

fn do_compare() -> Result<bool, Box<Error>> {
    let ldap = LdapConn::new("ldap://localhost:2389")?;
    let (res, _ctrls) = ldap.simple_bind("cn=Manager,dc=example,dc=org", "secret")?;
    if res.rc != 0 {
        return Err(res)?;
    }
    let cmp = ldap.compare(
        "uid=inejge,ou=People,dc=example,dc=org",
        "userPassword",
        "doublesecret"
    )?.equal()?;
    Ok(cmp)
}
