use std::str;

use super::{Exop, ExopParser};

use asnom::structures::Tag;

pub const WHOAMI_OID: &'static str = "1.3.6.1.4.1.4203.1.11.3";

pub struct WhoAmI;

pub struct WhoAmIResp {
    pub authzid: String
}

impl From<WhoAmI> for Vec<Tag> {
    fn from(_w: WhoAmI) -> Vec<Tag> {
        Exop {
            name: Some(WHOAMI_OID.to_owned()),
            val: None
        }.into()
    }
}

impl ExopParser for WhoAmIResp {
    fn parse(val: &[u8]) -> WhoAmIResp {
        WhoAmIResp {
            authzid: str::from_utf8(val).expect("authzid").to_owned()
        }
    }
}
