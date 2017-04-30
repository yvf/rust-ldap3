use std::collections::HashMap;

use asnom::structure::{PL, StructureTag};
use asnom::structures::{ASNTag, Boolean, OctetString, Sequence, Tag};
use asnom::universal::Types;

pub mod types {
    pub type ControlType = self::inner::_ControlType;
    pub use self::inner::_ControlType::{PagedResults, RelaxRules};
    mod inner {
        #[derive(Clone, Copy, Debug)]
        pub enum _ControlType {
            PagedResults,
            RelaxRules,
            #[doc(hidden)]
            _Nonexhaustive,
        }
    }
}
use self::types::ControlType;

mod paged_results;
pub use self::paged_results::PagedResults;

mod relax_rules;
pub use self::relax_rules::RelaxRules;

lazy_static! {
    static ref CONTROLS: HashMap<&'static str, ControlType> = {
        let mut map = HashMap::new();
        map.insert(self::paged_results::PAGED_RESULTS_OID, types::PagedResults);
        map
    };
}

pub trait MakeCritical {
    fn critical(self) -> CriticalControl<Self> where Self: Sized {
        CriticalControl {
            control: self,
        }
    }
}

pub struct CriticalControl<T> {
    control: T
}

impl<T> From<CriticalControl<T>> for StructureTag
    where T: Oid, Option<Vec<u8>>: From<T>
{
    fn from(cc: CriticalControl<T>) -> StructureTag {
        let oid = cc.control.oid();
        construct_control(oid, true, cc.control.into())
    }
}

pub trait Oid {
    fn oid(&self) -> &'static str;
}

pub trait ControlParser {
    fn parse(&[u8]) -> Self;
}

pub fn parse_control<T: ControlParser>(val: &[u8]) -> T {
    T::parse(val)
}

#[derive(Clone, Debug)]
pub struct Control(pub Option<ControlType>, pub RawControl);

#[derive(Clone, Debug)]
pub struct RawControl {
    pub ctype: String,
    pub crit: bool,
    pub val: Option<Vec<u8>>,
}

impl From<RawControl> for StructureTag {
    fn from(ctrl: RawControl) -> StructureTag {
        construct_control(&ctrl.ctype, ctrl.crit, ctrl.val)
    }
}

pub fn construct_control(oid: &str, crit: bool, val: Option<Vec<u8>>) -> StructureTag {
    let mut seq = vec![
        Tag::OctetString(OctetString {
            inner: Vec::from(oid.as_bytes()),
            .. Default::default()
        })
    ];
    if crit {
        seq.push(Tag::Boolean(Boolean {
            inner: true,
            .. Default::default()
        }));
    }
    if let Some(val) = val {
        seq.push(Tag::OctetString(OctetString {
            inner: val,
            .. Default::default()
        }));
    }
    Tag::Sequence(Sequence {
        inner: seq,
        .. Default::default()
    }).into_structure()
}

pub fn parse_controls(t: StructureTag) -> Vec<Control> {
    let tags = t.expect_constructed().expect("result sequence").into_iter();
    let mut ctrls = Vec::new();
    for ctrl in tags {
        let mut components = ctrl.expect_constructed().expect("components").into_iter();
        let ctype = String::from_utf8(components.next().expect("element").expect_primitive().expect("octet string")).expect("control type");
        let next = components.next();
        let (crit, maybe_val) = match next {
            None => (false, None),
            Some(c) => match c {
                StructureTag { id, class: _, ref payload } if id == Types::Boolean as u64 => match *payload {
                    PL::P(ref v) => (v[0] != 0, components.next()),
                    PL::C(_) => panic!("decoding error"),
                },
                StructureTag { id, class: _, payload: _ } if id == Types::OctetString as u64 => (false, Some(c.clone())),
                _ => panic!("decoding error"),
            },
        };
        let val = match maybe_val {
            None => None,
            Some(v) => Some(Vec::from(v.expect_primitive().expect("octet string"))),
        };
        let known_type = match CONTROLS.get(&*ctype) {
            Some(val) => Some(*val),
            None => None,
        };
        ctrls.push(Control(known_type, RawControl { ctype: ctype, crit: crit, val: val }));
    }
    ctrls
}
