use super::{MakeCritical, Oid};
use super::construct_control;

use lber::structure::StructureTag;

pub struct RelaxRules;

pub const RELAX_RULES_OID: &'static str = "1.3.6.1.4.1.4203.666.5.12";

impl Oid for RelaxRules {
    fn oid(&self) -> &'static str {
        RELAX_RULES_OID
    }
}

impl MakeCritical for RelaxRules { }

impl From<RelaxRules> for Option<Vec<u8>> {
    fn from(_rr: RelaxRules) -> Option<Vec<u8>> {
        None
    }
}

impl From<RelaxRules> for StructureTag {
    fn from(_rr: RelaxRules) -> StructureTag {
        construct_control(RELAX_RULES_OID, false, None)
    }
}
