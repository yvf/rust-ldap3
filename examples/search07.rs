use ldap3::{LdapConnAsync, Scope, SearchEntry};

use tokio::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldapi://ldapi").await?;
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            dbg!(e);
        }
    });
    let res = ldap.sasl_external_bind().await?.success()?;
    dbg!(res);
    let mut search = ldap.into_search_stream();
    search
        .start(
            "cn=MailACLs, o=local",
            Scope::Subtree,
            "cn:dn:=MailACLs",
            vec!["*"],
        )
        .await?;
    while let Some(re) = search.next().await? {
        let se = SearchEntry::construct(re);
        dbg!(se);
    }
    let (res, _ldap) = search.finish();
    dbg!(res);
    Ok(())
}
