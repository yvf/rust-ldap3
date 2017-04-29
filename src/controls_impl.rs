use bytes::BytesMut;

use asnom::common::TagClass;
use asnom::IResult;
use asnom::parse::{parse_uint, parse_tag};
use asnom::structure::{PL, StructureTag};
use asnom::structures::{ASNTag, Boolean, Integer, OctetString, Sequence, Tag};
use asnom::universal::Types;
use asnom::write;

#[derive(Clone, Debug)]
pub struct RawControl {
    pub ctype: String,
    pub crit: bool,
    pub val: Option<Vec<u8>>,
}

impl From<RawControl> for StructureTag {
    fn from(rc: RawControl) -> StructureTag {
        construct_control(&rc.ctype, rc.crit, rc.val)
    }
}

#[derive(Clone, Debug)]
pub struct PagedResults {
    pub size: i32,
    pub cookie: Vec<u8>,
}

impl PagedResults {
    pub fn req(size: i32, cookie: &[u8], crit: bool) -> StructureTag {
        let cval = Tag::Sequence(Sequence {
            inner: vec![
                Tag::Integer(Integer {
                    inner: size as i64,
                    .. Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: Vec::from(cookie),
                    .. Default::default()
                }),
            ],
            .. Default::default()
        }).into_structure();
        let mut buf = BytesMut::with_capacity(cookie.len() + 16);
        write::encode_into(&mut buf, cval).expect("encoded");
        construct_control("1.2.840.113556.1.4.319", crit, Some(Vec::from(&buf[..])))
    }
}

pub struct RelaxRules;

impl RelaxRules {
    pub fn req() -> StructureTag {
        construct_control("1.3.6.1.4.1.4203.666.5.12", true, None)
    }
}

#[derive(Clone, Debug)]
pub enum Control {
    PagedResults(PagedResults, bool),
    Raw(RawControl),
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
        let parsed = match &*ctype {
            "1.2.840.113556.1.4.319" => {
                let mut pr_comps = match parse_tag(val.expect("paged results control value").as_ref()) {
                    IResult::Done(_, tag) => tag,
                    _ => panic!("failed to parse paged results value components"),
                }.expect_constructed().expect("paged results components").into_iter();
                let size = match parse_uint(pr_comps.next().expect("element")
                        .match_class(TagClass::Universal)
                        .and_then(|t| t.match_id(Types::Integer as u64))
                        .and_then(|t| t.expect_primitive()).expect("paged results size")
                        .as_slice()) {
                    IResult::Done(_, size) => size as i32,
                    _ => panic!("failed to parse size"),
                };
                let cookie = pr_comps.next().expect("element").expect_primitive().expect("octet string");
                Control::PagedResults(PagedResults { size: size, cookie: cookie }, crit)
            }
            _ => Control::Raw(RawControl { ctype: ctype, crit: crit, val: val }),
        };
        ctrls.push(parsed);
    }
    ctrls
}
