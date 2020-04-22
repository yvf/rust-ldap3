use ldap3::{LdapConnAsync, LdapError};
use ldap3::controls::ProxyAuth;
use ldap3::exop::{WhoAmI, WhoAmIResp};

#[tokio::main]
async fn main() -> Result<(), LdapError> {
    let (conn, mut ldap) = LdapConnAsync::new("ldapi://ldapi").await?;
    ldap3::drive!(conn);
    ldap.simple_bind("cn=proxy,dc=example,dc=org", "topsecret")
        .await?
        .success()?;
    let (exop, _res) = ldap
        .with_controls(ProxyAuth {
            authzid: "dn:cn=proxieduser,dc=example,dc=org".to_owned(),
        })
        .extended(WhoAmI)
        .await?
        .success()?;
    let whoami: WhoAmIResp = exop.parse();
    println!("{}", whoami.authzid);
    Ok(())
}
