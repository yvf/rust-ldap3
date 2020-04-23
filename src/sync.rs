use crate::conn::LdapConnAsync;
use crate::exop::Exop;
use crate::ldap::Ldap;
use crate::result::{ExopResult, LdapResult, Result};

use tokio::runtime::{self, Runtime};

pub struct LdapConn {
    ldap: Ldap,
    rt: Runtime,
}

impl LdapConn {
    pub fn new(url: &str) -> Result<Self> {
        let mut rt = runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()?;
        let ldap = rt.block_on(async move {
            let (conn, ldap) = match LdapConnAsync::new(url).await {
                Ok((conn, ldap)) => (conn, ldap),
                Err(e) => return Err(e),
            };
            super::drive!(conn);
            Ok(ldap)
        })?;
        Ok(LdapConn { ldap, rt })
    }

    pub fn simple_bind(&mut self, bind_dn: &str, bind_pw: &str) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.simple_bind(bind_dn, bind_pw).await })
    }

    pub fn sasl_external_bind(&mut self) -> Result<LdapResult> {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.sasl_external_bind().await })
    }

    pub fn extended<E>(&mut self, exop: E) -> Result<ExopResult>
    where
        E: Into<Exop>,
    {
        let rt = &mut self.rt;
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.extended(exop).await })
    }
}
