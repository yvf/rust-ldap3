use ldap3::result::Result;
use ldap3::{LdapConnAsync, Scope};

#[tokio::main]
async fn main() -> Result<()> {
    let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:2389").await?;
    ldap3::drive!(conn);
    let mut stream = ldap
        .streaming_search(
            "ou=Places,dc=example,dc=org",
            Scope::Subtree,
            "objectClass=locality",
            vec!["l"],
        )
        .await?;
    while let Some(_r) = stream.next().await? {
        break;
    }
    let msgid = stream.ldap_handle().last_id();
    let _res = stream.finish().await;
    ldap.abandon(msgid).await?;
    Ok(ldap.unbind().await?)
}
