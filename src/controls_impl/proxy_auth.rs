use super::Oid;
use super::construct_control;

use lber::structure::StructureTag;

/// Proxy Authorization control ([RFC 4370](https://tools.ietf.org/html/rfc4370)).
///
/// This control only has the request part, and must be marked as critical.
/// For that reason, it doesn't implement `MakeCritical`.
#[derive(Clone, Debug)]
pub struct ProxyAuth {
    /// Authorization identity, empty if anonymous.
    pub authzid: String,
}

pub const PROXY_AUTH_OID: &'static str = "2.16.840.1.113730.3.4.18";

impl Oid for ProxyAuth {
    fn oid(&self) -> &'static str {
        PROXY_AUTH_OID
    }
}

impl From<ProxyAuth> for Option<Vec<u8>> {
    fn from(pa: ProxyAuth) -> Option<Vec<u8>> {
        Some(pa.authzid.into_bytes())
    }
}

impl From<ProxyAuth> for StructureTag {
    fn from(pa: ProxyAuth) -> StructureTag {
        construct_control(PROXY_AUTH_OID, true, pa.into())
    }
}
