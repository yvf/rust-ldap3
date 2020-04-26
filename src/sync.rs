use std::collections::HashSet;
use std::hash::Hash;
use std::sync::Arc;

use crate::conn::{LdapConnAsync, LdapConnSettings};
use crate::exop::Exop;
use crate::ldap::{Ldap, Mod};
use crate::result::{CompareResult, ExopResult, LdapResult, Result, SearchResult};
use crate::search::{ResultEntry, Scope, SearchStream};
use crate::RequestId;

use tokio::runtime::{self, Runtime};

#[derive(Debug)]
pub struct LdapConn {
    rt: Arc<Runtime>,
    ldap: Ldap,
}

impl LdapConn {
    pub fn new(url: &str) -> Result<Self> {
        Self::with_settings(LdapConnSettings::new(), url)
    }

    pub fn with_settings(settings: LdapConnSettings, url: &str) -> Result<Self> {
        let mut rt = runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()?;
        let ldap = rt.block_on(async move {
            let (conn, ldap) = match LdapConnAsync::with_settings(settings, url).await {
                Ok((conn, ldap)) => (conn, ldap),
                Err(e) => return Err(e),
            };
            super::drive!(conn);
            Ok(ldap)
        })?;
        Ok(LdapConn {
            ldap,
            rt: Arc::new(rt),
        })
    }

    pub fn simple_bind(&mut self, bind_dn: &str, bind_pw: &str) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.simple_bind(bind_dn, bind_pw).await })
    }

    pub fn sasl_external_bind(&mut self) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.sasl_external_bind().await })
    }

    pub fn search<S: AsRef<str>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<S>,
    ) -> Result<SearchResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.search(base, scope, filter, attrs).await })
    }

    pub fn streaming_search<S: AsRef<str>>(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: Vec<S>,
    ) -> Result<EntryStream> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        let stream =
            rt.block_on(async move { ldap.streaming_search(base, scope, filter, attrs).await })?;
        Ok(EntryStream {
            stream,
            rt: self.rt.clone(),
        })
    }

    pub fn add<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        attrs: Vec<(S, HashSet<S>)>,
    ) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.add(dn, attrs).await })
    }

    pub fn compare<B: AsRef<[u8]>>(
        &mut self,
        dn: &str,
        attr: &str,
        val: B,
    ) -> Result<CompareResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.compare(dn, attr, val).await })
    }

    pub fn delete(&mut self, dn: &str) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.delete(dn).await })
    }

    pub fn modify<S: AsRef<[u8]> + Eq + Hash>(
        &mut self,
        dn: &str,
        mods: Vec<Mod<S>>,
    ) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.modify(dn, mods).await })
    }

    pub fn modifydn(
        &mut self,
        dn: &str,
        rdn: &str,
        delete_old: bool,
        new_sup: Option<&str>,
    ) -> Result<LdapResult> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.modifydn(dn, rdn, delete_old, new_sup).await })
    }

    pub fn unbind(&mut self) -> Result<()> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.unbind().await })
    }

    pub fn extended<E>(&mut self, exop: E) -> Result<ExopResult>
    where
        E: Into<Exop>,
    {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.extended(exop).await })
    }

    pub fn last_id(&mut self) -> RequestId {
        self.ldap.last_id()
    }

    pub fn abandon(&mut self, msgid: RequestId) -> Result<()> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let ldap = &mut self.ldap;
        rt.block_on(async move { ldap.abandon(msgid).await })
    }
}

pub struct EntryStream {
    stream: SearchStream,
    rt: Arc<Runtime>,
}

impl EntryStream {
    pub fn next(&mut self) -> Result<Option<ResultEntry>> {
        let rt = Arc::get_mut(&mut self.rt).expect("runtime ref");
        let stream = &mut self.stream;
        rt.block_on(async move { stream.next().await })
    }

    pub fn result(self) -> LdapResult {
        self.stream.finish()
    }
}
