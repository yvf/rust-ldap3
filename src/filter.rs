use std::default::Default;
use std::str;

use nom::IResult;
use nom::{be_u8, digit, is_alphabetic, is_alphanumeric};

use asnom::common::TagClass;
use asnom::structures::{Boolean, ExplicitTag, OctetString, Sequence, Tag};

pub fn parse(input: &str) -> Result<Tag, ()> {
    match filtexpr(input.as_bytes()) {
        IResult::Done(r, t) => {
            if r.is_empty() {
                Ok(t)
            } else {
                Err(())
            }
        },
        IResult::Error(_) | IResult::Incomplete(_) => Err(()),
    }
}

named!(filtexpr<Tag>, alt!(filter | item));

named!(filter<Tag>, delimited!(char!('('), filtercomp, char!(')')));
named!(filtercomp<Tag>, alt!(and | or | not | item));
named!(filterlist<Vec<Tag>>, many1!(filter));

named!(and<Tag>, map!(preceded!(char!('&'), filterlist),
    |tagv: Vec<Tag>| -> Tag {
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: 0,
            inner: tagv,
        })
    }
));

named!(or<Tag>, map!(preceded!(char!('|'), filterlist),
    |tagv: Vec<Tag>| -> Tag {
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: 1,
            inner: tagv,
        })
    }
));

named!(not<Tag>, map!(preceded!(char!('!'), filter),
    |tag: Tag| -> Tag {
        Tag::ExplicitTag(ExplicitTag {
            class: TagClass::Context,
            id: 2,
            inner: Box::new(tag),
        })
    }
));

named!(item<Tag>, alt!(non_extensible | extensible));

const EQ_MATCH: u64 = 3;

named!(non_extensible<Tag>, do_parse!(
    attr: attributedescription >>
    filtertype: filtertype >>
    value: verify!(take_while!(is_value_char), |v: &[u8]| !str::from_utf8(v).expect("assertion value").contains("**")) >> ({
        if filtertype != EQ_MATCH || !value.contains(&b'*') {
            simple_tag(attr, filtertype, value)
        } else {
            if value.len() == 1 && value[0] == b'*' {
                present_tag(attr)
            } else {
                substr_tag(attr, value)
            }
        }
    })
));

fn is_value_char(c: u8) -> bool {
    c != 0 && c != b'(' && c != b')' && c != b'\\'
}

named!(filtertype<u64>, alt!(
    char!('=') => { |_| 3 } |
    tag!(">=") => { |_| 5 } |
    tag!("<=") => { |_| 6 } |
    tag!("~=") => { |_| 8 }
));

fn simple_tag(attr: &[u8], filtertype: u64, value: &[u8]) -> Tag {
    Tag::Sequence(Sequence {
        class: TagClass::Context,
        id: filtertype,
        inner: vec![
               Tag::OctetString(OctetString {
                   inner: attr.to_vec(),
                   .. Default::default()
               }),
               Tag::OctetString(OctetString {
                   inner: value.to_vec(),
                   .. Default::default()
               })
        ]
    })
}

fn present_tag(attr: &[u8]) -> Tag {
    (Tag::OctetString(OctetString {
        class: TagClass::Context,
        id: 7,
        inner: attr.to_vec(),
    }))
}

const SUB_MATCH: u64 = 4;

const SUB_INITIAL: u64 = 0;
const SUB_ANY: u64 = 1;
const SUB_FINAL: u64 = 2;

fn substr_tag(attr: &[u8], value: &[u8]) -> Tag {
    let mut inner = vec![];
    let mut first = true;
    let mut replace_last = true;
    for sub_elem in value.split(|&b| b == b'*') {
        if first {
            first = false;
            if !sub_elem.is_empty() {
                inner.push(Tag::OctetString(OctetString {
                    class: TagClass::Context,
                    id: SUB_INITIAL,
                    inner: sub_elem.to_vec(),
                }));
            }
        } else {
            if sub_elem.is_empty() {
                replace_last = false;
            } else {
                inner.push(Tag::OctetString(OctetString {
                    class: TagClass::Context,
                    id: SUB_ANY,
                    inner: sub_elem.to_vec(),
                }));
            }
        }
    }
    if replace_last {
        let mut last_elem = inner.pop().expect("last element");
        match last_elem {
            Tag::OctetString(ref mut o) => { o.id = SUB_FINAL; },
            _ => unimplemented!(),
        }
        inner.push(last_elem);
    }
    Tag::Sequence(Sequence {
        class: TagClass::Context,
        id: SUB_MATCH,
        inner: vec![
               Tag::OctetString(OctetString {
                   inner: attr.to_vec(),
                   .. Default::default()
               }),
               Tag::Sequence(Sequence {
                   inner: inner,
                   .. Default::default()
               })
        ]
    })
}

named!(extensible<Tag>, alt!(attr_dn_mrule | dn_mrule));

named!(attr_dn_mrule<Tag>, do_parse!(
    attr: attributedescription >>
    dn: opt!(tag!(":dn")) >>
    mrule: opt!(preceded!(char!(':'), attributetype)) >>
    tag!(":=") >>
    value: take_while!(is_ext_value_char) >>
    (extensible_tag(mrule, Some(attr), value, dn.is_some()))
));

named!(dn_mrule<Tag>, do_parse!(
    dn: opt!(tag!(":dn")) >>
    mrule: preceded!(char!(':'), attributetype) >>
    tag!(":=") >>
    value: take_while!(is_ext_value_char) >>
    (extensible_tag(Some(mrule), None, value, dn.is_some()))
));

fn is_ext_value_char(c: u8) -> bool {
    is_value_char(c) && c != b'*'
}

fn extensible_tag(mrule: Option<&[u8]>, attr: Option<&[u8]>, value: &[u8], dn: bool) -> Tag {
    let mut inner = vec![];
    if let Some(mrule) = mrule {
        inner.push(Tag::OctetString(OctetString {
            class: TagClass::Context,
            id: 1,
            inner: mrule.to_vec()
        }));
    }
    if let Some(attr) = attr {
        inner.push(Tag::OctetString(OctetString {
            class: TagClass::Context,
            id: 2,
            inner: attr.to_vec()
        }));
    }
    inner.push(Tag::OctetString(OctetString {
        class: TagClass::Context,
        id: 3,
        inner: value.to_vec()
    }));
    if dn {
        inner.push(Tag::Boolean(Boolean {
            class: TagClass::Context,
            id: 4,
            inner: dn
        }));
    }
    Tag::Sequence(Sequence {
        class: TagClass::Context,
        id: 9,
        inner: inner
    })
}

named!(attributedescription<&[u8]>, recognize!(do_parse!(
    _type: attributetype >>
    _opts: many0!(preceded!(char!(';'), take_while1!(is_alnum_hyphen))) >> ()
)));

named!(attributetype<&[u8]>, alt!(numericoid | descr));

named!(numericoid<&[u8]>, recognize!(
    do_parse!(
        _leading: number >>
        _rest: many0!(preceded!(char!('.'), number)) >> ()
    )
));

named!(number<&[u8]>, verify!(digit, |d: &[u8]| d.len() == 1 || d[0] != b'0'));

named!(descr<&[u8]>, recognize!(
    do_parse!(
        _leading: verify!(be_u8, |a: u8| is_alphabetic(a)) >>
        _rest: take_while!(is_alnum_hyphen) >> ()
    )
));

fn is_alnum_hyphen(c: u8) -> bool {
    is_alphanumeric(c) || c == b'-'
}
