use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use tokio::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let (conn, ldap) = LdapConnAsync::with_settings(
        LdapConnSettings::new().set_starttls(true),
        "ldap://localhost",
    )
    .await?;
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            dbg!(e);
        }
    });
    let mut search = ldap.into_search_stream();
    search
        .start("", Scope::Base, "objectClass=*", vec!["+"])
        .await?;
    while let Some(re) = search.next().await? {
        let se = SearchEntry::construct(re);
        dbg!(se);
    }
    let (res, _ldap) = search.finish();
    dbg!(res);
    Ok(())
}
