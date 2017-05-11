use std::collections::HashMap;

use lber::structure::{PL, StructureTag};
use lber::structures::{ASNTag, Boolean, OctetString, Sequence, Tag};
use lber::universal::Types;

pub mod types {
    //! Control type enum and variant names.
    //!
    //! Variants are individually reexported from the private submodule
    //! to inhibit exhaustive matching.
    pub use self::inner::_ControlType::{PagedResults, RelaxRules};

    /// Recognized control types. Variants can't be named in the namespace
    /// of this type; they must be used through module-level reexports.
    pub type ControlType = self::inner::_ControlType;
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

/// Mark a control as critical.
///
/// Every control provided by this library implements this trait. All controls
/// are instantiated as non-critical by default.
///
/// __Note__: a way to implement this trait for third-party controls will be
/// provided in 0.5.x.
pub trait MakeCritical {
    /// Mark the control instance as critical. This operation consumes the control,
    /// and is irreversible.
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

/// Parse the raw value of a control.
///
/// The function returns the struct corresponding to control's contents.
/// The type of the struct must be explicitly specified in the binding annotation
/// of a __let__ statement or by using the turbofish.
///
/// __Note__: This function will be removed in 0.5.x, in favor of calling
/// type-qualified `parse()` on `RawControl`.
pub fn parse_control<T: ControlParser>(val: &[u8]) -> T {
    T::parse(val)
}

/// Response control.
///
/// If the OID is recognized as corresponding to one of controls implemented by this
/// library while parsing raw BER data of the response, the first element will have
/// a value, otherwise it will be `None`.
#[derive(Clone, Debug)]
pub struct Control(pub Option<ControlType>, pub RawControl);

/// Generic control.
///
/// This struct can be used both for request and response controls. For requests, an
/// independently implemented control can produce an instance of this type and use it
/// to provide an element of the vector passed to [`with_controls()`](../struct.LdapConn.html#method.with_controls)
/// by calling `into()` on the instance. For responses, an instance is packed into a
/// [`Control`](struct.Control.html).
// future text:
// ... and can be parsed by calling type-qualified [`parse()`](#method.parse) on that
// instance, if a [`ControlParser`](trait.ControlParser.html) implementation exists
// for the specified type.
#[derive(Clone, Debug)]
pub struct RawControl {
    /// OID of the control.
    pub ctype: String,
    /// Criticality, has no meaning on response.
    pub crit: bool,
    /// Raw value of the control, if any.
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
                StructureTag { id, ref payload, .. } if id == Types::Boolean as u64 => match *payload {
                    PL::P(ref v) => (v[0] != 0, components.next()),
                    PL::C(_) => panic!("decoding error"),
                },
                StructureTag { id, .. } if id == Types::OctetString as u64 => (false, Some(c.clone())),
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
