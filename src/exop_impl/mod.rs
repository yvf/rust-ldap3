use lber::common::TagClass;
use lber::structures::{OctetString, Tag};

mod whoami;
pub use self::whoami::{WhoAmI, WhoAmIResp};

/// Generic extended operation.
///
/// Since the same struct can be used both for requests and responses,
/// both fields must be declared as optional; when sending an extended
/// request, `name` must not be `None`.
#[derive(Clone, Debug)]
pub struct Exop {
    /// OID of the operation. It may be absent in the response.
    pub name: Option<String>,
    /// Request or response value. It may be absent in both cases.
    pub val: Option<Vec<u8>>,
}

pub trait ExopParser {
    fn parse(&[u8]) -> Self;
}

/// Parse the raw exop value.
///
/// Since the function is generic, the return type must be explicitly
/// specified in the binding annotation of a __let__ statement or by
/// using the turbofish.
///
/// __Note__: this function will be removed in 0.5.x, in favor of calling
/// type-qualified `parse()` on `Exop`.
pub fn parse_exop<T: ExopParser>(val: &[u8]) -> T {
    T::parse(val)
}

impl From<Exop> for Vec<Tag> {
    fn from(exop: Exop) -> Vec<Tag> {
        construct_exop(exop)
    }
}

pub fn construct_exop(exop: Exop) -> Vec<Tag> {
    assert!(exop.name.is_some());
    let mut seq = vec![
        Tag::OctetString(OctetString {
            id: 0,
            class: TagClass::Context,
            inner: exop.name.unwrap().into_bytes()
        })
    ];
    if let Some(val) = exop.val {
        seq.push(Tag::OctetString(OctetString {
            id: 1,
            class: TagClass::Context,
            inner: val
        }));
    }
    seq
}
