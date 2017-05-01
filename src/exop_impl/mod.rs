use asnom::common::TagClass;
use asnom::structures::{OctetString, Tag};

mod whoami;
pub use self::whoami::{WhoAmI, WhoAmIResp};

#[derive(Clone, Debug)]
pub struct Exop {
    pub name: Option<String>,
    pub val: Option<Vec<u8>>,
}

pub trait ExopParser {
    fn parse(&[u8]) -> Self;
}

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
