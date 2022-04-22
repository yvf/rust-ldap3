#![allow(clippy::blocks_in_if_conditions)]
#![allow(clippy::result_unit_err)]

use std::default::Default;
use std::str;

use lber::common::TagClass;
use lber::structures::{Boolean, ExplicitTag, OctetString, Sequence, Tag};

use nom::IResult;
use nom::{be_u8, digit, is_alphabetic, is_alphanumeric, is_hex_digit};

#[doc(hidden)]
pub fn parse(input: &str) -> Result<Tag, ()> {
    match filtexpr(input.as_bytes()) {
        IResult::Done(r, t) => {
            if r.is_empty() {
                Ok(t)
            } else {
                Err(())
            }
        }
        IResult::Error(_) | IResult::Incomplete(_) => Err(()),
    }
}

pub(crate) fn parse_matched_values(input: &str) -> Result<Tag, ()> {
    match mv_filtexpr(input.as_bytes()) {
        IResult::Done(r, t) => {
            if r.is_empty() {
                Ok(t)
            } else {
                Err(())
            }
        }
        IResult::Error(_) | IResult::Incomplete(_) => Err(()),
    }
}

const AND_FILT: u64 = 0;
const OR_FILT: u64 = 1;
const NOT_FILT: u64 = 2;

const EQ_MATCH: u64 = 3;
const SUBSTR_MATCH: u64 = 4;
const GTE_MATCH: u64 = 5;
const LTE_MATCH: u64 = 6;
const PRES_MATCH: u64 = 7;
const APPROX_MATCH: u64 = 8;
const EXT_MATCH: u64 = 9;

const SUB_INITIAL: u64 = 0;
const SUB_ANY: u64 = 1;
const SUB_FINAL: u64 = 2;

named!(filtexpr<Tag>, alt!(filter | item));

named!(filter<Tag>, delimited!(char!('('), filtercomp, char!(')')));
named!(filtercomp<Tag>, alt!(and | or | not | item));
named!(filterlist<Vec<Tag>>, many0!(filter));

named!(
    mv_filtexpr<Tag>,
    delimited!(char!('('), mv_filterlist, char!(')'))
);
named!(
    mv_filteritems<Vec<Tag>>,
    many1!(delimited!(char!('('), item, char!(')')))
);
named!(
    mv_filterlist<Tag>,
    map!(mv_filteritems, |tagv: Vec<Tag>| -> Tag {
        Tag::Sequence(Sequence {
            inner: tagv,
            ..Default::default()
        })
    })
);

named!(
    and<Tag>,
    map!(preceded!(char!('&'), filterlist), |tagv: Vec<Tag>| -> Tag {
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: AND_FILT,
            inner: tagv,
        })
    })
);

named!(
    or<Tag>,
    map!(preceded!(char!('|'), filterlist), |tagv: Vec<Tag>| -> Tag {
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: OR_FILT,
            inner: tagv,
        })
    })
);

named!(
    not<Tag>,
    map!(preceded!(char!('!'), filter), |tag: Tag| -> Tag {
        Tag::ExplicitTag(ExplicitTag {
            class: TagClass::Context,
            id: NOT_FILT,
            inner: Box::new(tag),
        })
    })
);

named!(item<Tag>, alt!(eq | non_eq | extensible));

pub(crate) enum Unescaper {
    WantFirst,
    WantSecond(u8),
    Value(u8),
    Error,
}

impl Unescaper {
    pub(crate) fn feed(&self, c: u8) -> Unescaper {
        match *self {
            Unescaper::Error => Unescaper::Error,
            Unescaper::WantFirst => {
                if is_hex_digit(c) {
                    Unescaper::WantSecond(
                        c - if c <= b'9' {
                            b'0'
                        } else {
                            (c & 0x20) + b'A' - 10
                        },
                    )
                } else {
                    Unescaper::Error
                }
            }
            Unescaper::WantSecond(partial) => {
                if is_hex_digit(c) {
                    Unescaper::Value(
                        (partial << 4)
                            + (c - if c <= b'9' {
                                b'0'
                            } else {
                                (c & 0x20) + b'A' - 10
                            }),
                    )
                } else {
                    Unescaper::Error
                }
            }
            Unescaper::Value(_v) => {
                if c != b'\\' {
                    Unescaper::Value(c)
                } else {
                    Unescaper::WantFirst
                }
            }
        }
    }
}

// Any byte in the assertion value may be represented by \NN, where N is a hex digit.
// Some characters must be represented in this way: parentheses, asterisk and backslash
// itself.
named!(
    unescaped<Vec<u8>>,
    map_res!(
        fold_many0!(
            verify!(be_u8, is_value_char),
            (Unescaper::Value(0), Vec::new()),
            |(mut u, mut vec): (Unescaper, Vec<_>), c: u8| {
                u = u.feed(c);
                if let Unescaper::Value(c) = u {
                    vec.push(c);
                }
                (u, vec)
            }
        ),
        |(u, vec): (Unescaper, Vec<_>)| -> Result<Vec<u8>, ()> {
            if let Unescaper::Value(_) = u {
                Ok(vec)
            } else {
                Err(())
            }
        }
    )
);

named!(
    non_eq<Tag>,
    do_parse!(
        attr: attributedescription
            >> filterop: alt!(tag!(">=") | tag!("<=") | tag!("~="))
            >> value: unescaped
            >> ({
                Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: filtertag(filterop),
                    inner: vec![
                        Tag::OctetString(OctetString {
                            inner: attr.to_vec(),
                            ..Default::default()
                        }),
                        Tag::OctetString(OctetString {
                            inner: value,
                            ..Default::default()
                        }),
                    ],
                })
            })
    )
);

fn filtertag(filterop: &[u8]) -> u64 {
    match filterop {
        b">=" => GTE_MATCH,
        b"<=" => LTE_MATCH,
        b"~=" => APPROX_MATCH,
        _ => unimplemented!(),
    }
}

named!(
    eq<Tag>,
    do_parse!(
        attr: attributedescription
            >> tag!("=")
            >> initial: unescaped
            >> mid_final:
                map_res!(many0!(preceded!(tag!("*"), unescaped)), |v: Vec<
                    Vec<u8>,
                >|
                 -> Result<
                    Vec<Vec<u8>>,
                    (),
                > {
                    // an empty element may exist only at the very end; otherwise, we have two adjacent asterisks
                    if v.iter().enumerate().fold(false, |acc, (n, ve)| {
                        acc || ve.is_empty() && n + 1 != v.len()
                    }) {
                        Err(())
                    } else {
                        Ok(v)
                    }
                })
            >> ({
                if mid_final.is_empty() {
                    // simple equality, no asterisks in assertion value
                    Tag::Sequence(Sequence {
                        class: TagClass::Context,
                        id: EQ_MATCH,
                        inner: vec![
                            Tag::OctetString(OctetString {
                                inner: attr.to_vec(),
                                ..Default::default()
                            }),
                            Tag::OctetString(OctetString {
                                inner: initial,
                                ..Default::default()
                            }),
                        ],
                    })
                } else if initial.is_empty() && mid_final.len() == 1 && mid_final[0].is_empty() {
                    // presence, single asterisk in assertion value
                    Tag::OctetString(OctetString {
                        class: TagClass::Context,
                        id: PRES_MATCH,
                        inner: attr.to_vec(),
                    })
                } else {
                    // substring match
                    let mut inner = vec![];
                    if !initial.is_empty() {
                        inner.push(Tag::OctetString(OctetString {
                            class: TagClass::Context,
                            id: SUB_INITIAL,
                            inner: initial,
                        }));
                    }
                    let n = mid_final.len();
                    for (i, sub_elem) in mid_final.into_iter().enumerate() {
                        if sub_elem.is_empty() {
                            break;
                        }
                        inner.push(Tag::OctetString(OctetString {
                            class: TagClass::Context,
                            id: if i + 1 != n { SUB_ANY } else { SUB_FINAL },
                            inner: sub_elem,
                        }));
                    }
                    Tag::Sequence(Sequence {
                        class: TagClass::Context,
                        id: SUBSTR_MATCH,
                        inner: vec![
                            Tag::OctetString(OctetString {
                                inner: attr.to_vec(),
                                ..Default::default()
                            }),
                            Tag::Sequence(Sequence {
                                inner,
                                ..Default::default()
                            }),
                        ],
                    })
                }
            })
    )
);

fn is_value_char(c: u8) -> bool {
    c != 0 && c != b'(' && c != b')' && c != b'*'
}

named!(extensible<Tag>, alt!(attr_dn_mrule | dn_mrule));

named!(
    attr_dn_mrule<Tag>,
    do_parse!(
        attr: attributedescription
            >> dn: opt!(tag!(":dn"))
            >> mrule: opt!(preceded!(char!(':'), attributetype))
            >> tag!(":=")
            >> value: unescaped
            >> (extensible_tag(mrule, Some(attr), value, dn.is_some()))
    )
);

named!(
    dn_mrule<Tag>,
    do_parse!(
        dn: opt!(tag!(":dn"))
            >> mrule: preceded!(char!(':'), attributetype)
            >> tag!(":=")
            >> value: unescaped
            >> (extensible_tag(Some(mrule), None, value, dn.is_some()))
    )
);

fn extensible_tag(mrule: Option<&[u8]>, attr: Option<&[u8]>, value: Vec<u8>, dn: bool) -> Tag {
    let mut inner = vec![];
    if let Some(mrule) = mrule {
        inner.push(Tag::OctetString(OctetString {
            class: TagClass::Context,
            id: 1,
            inner: mrule.to_vec(),
        }));
    }
    if let Some(attr) = attr {
        inner.push(Tag::OctetString(OctetString {
            class: TagClass::Context,
            id: 2,
            inner: attr.to_vec(),
        }));
    }
    inner.push(Tag::OctetString(OctetString {
        class: TagClass::Context,
        id: 3,
        inner: value,
    }));
    if dn {
        inner.push(Tag::Boolean(Boolean {
            class: TagClass::Context,
            id: 4,
            inner: dn,
        }));
    }
    Tag::Sequence(Sequence {
        class: TagClass::Context,
        id: EXT_MATCH,
        inner,
    })
}

named!(
    attributedescription<&[u8]>,
    recognize!(do_parse!(
        _type: attributetype
            >> _opts: many0!(preceded!(char!(';'), take_while1!(is_alnum_hyphen)))
            >> ()
    ))
);

named!(attributetype<&[u8]>, alt!(numericoid | descr));

named!(
    numericoid<&[u8]>,
    recognize!(do_parse!(
        _leading: number >> _rest: many0!(preceded!(char!('.'), number)) >> ()
    ))
);

// A number may be zero, but must not have superfluous leading zeroes
named!(
    number<&[u8]>,
    verify!(digit, |d: &[u8]| d.len() == 1 || d[0] != b'0')
);

named!(
    descr<&[u8]>,
    recognize!(do_parse!(
        _leading: verify!(be_u8, is_alphabetic) >> _rest: take_while!(is_alnum_hyphen) >> ()
    ))
);

fn is_alnum_hyphen(c: u8) -> bool {
    is_alphanumeric(c) || c == b'-'
}
