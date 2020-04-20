use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::LdapConnAsync;

use tokio::io;
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> io::Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldapi://ldapi").await?;
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            dbg!(e);
        }
    });
    let to = Some(Duration::from_secs(200));
    let _res = match to {
        Some(dur) => timeout(dur, ldap.sasl_external_bind()).await.map_err(|e| {
            dbg!(&e);
            e
        })?,
        None => ldap.sasl_external_bind().await,
    }?
    .success()?;
    dbg!(_res);
    let (exop, _res) = ldap.extended(WhoAmI).await?.success()?;
    let whoami: WhoAmIResp = exop.parse();
    dbg!(whoami);
    Ok(())
}
