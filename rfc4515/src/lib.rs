#[macro_use]
extern crate nom;
extern crate asnom;

use std::default::Default;

use nom::IResult;

use asnom::common::TagClass;
use asnom::structures::{Tag, Sequence, OctetString, ExplicitTag};

pub fn parse(input: &str) -> Result<Tag, ()> {
    match filter(input.as_bytes()) {
        IResult::Done(_, t) => Ok(t),
        IResult::Error(_) | IResult::Incomplete(_) => Err(()),
    }
}

named!(filter <Tag>, delimited!(char!('('), content, char!(')')));
named!(filterlist <Vec<Tag>>, many1!(filter));
named!(content <Tag>, alt!(and | or | not | match_f));

named!(and <Tag>, map!(preceded!( char!('&'), filterlist),
    | tagv: Vec<Tag> | -> Tag {
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: 0,
            inner: tagv,
        })
    }
));
named!(or <Tag>, map!(preceded!( char!('|'), filterlist),
    | tagv: Vec<Tag> | -> Tag {
        Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: 1,
            inner: tagv,
        })
    }
));
named!(not <Tag>, map!(preceded!( char!('!'), filter),
    | tag: Tag | -> Tag {
        Tag::ExplicitTag(ExplicitTag {
            class: TagClass::Context,
            id: 2,
            inner: Box::new(tag),
        })
    }
));

named!(match_f <Tag>, alt!(present | simple));

named!(present <Tag>, do_parse!(
    attr: take_till!(is_delimiter) >>
    tag!("=*") >>
    (Tag::OctetString(OctetString {
        class: TagClass::Context,
        id: 7,
        inner: attr.to_vec(),
    }))
));

named!(simple <Tag>, do_parse!(
    attr: take_till!(is_delimiter) >>
    filtertype: filtertype >>
    value: take_until!(")") >>
    (Tag::Sequence(Sequence {
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
    }))
));

named!(filtertype <u64>, alt!(
    char!('=') => { |_| 3 } |
    tag!(">=") => { |_| 5 } |
    tag!("<=") => { |_| 6 } |
    tag!("~=") => { |_| 8 }
));

pub fn is_delimiter(chr: u8) -> bool {
    chr == b'=' ||
    chr == b'<' ||
    chr == b'>' ||
    chr == b'~'
}

#[cfg(test)]
mod tests {

    use super::*;

    use std::default::Default;
    use asnom::common::TagClass;
    use asnom::structures::{Tag, OctetString, Sequence, ExplicitTag};

    #[test]
    fn present() {
        let f = "(objectClass=*)";

        let tag = Tag::OctetString(OctetString {
            class: TagClass::Context,
            id: 7,
            inner: vec![
                0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73
            ],
        });

        assert_eq!(parse(f), Ok(tag));
    }

    #[test]
    fn simple() {
        let f = "(cn=Babs Jensen)";

        let tag = Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: 3,
            inner: vec![
                   Tag::OctetString(OctetString {
                       inner: vec![0x63, 0x6e],
                       .. Default::default()
                   }),
                   Tag::OctetString(OctetString {
                       inner: vec![0x42, 0x61, 0x62, 0x73, 0x20, 0x4a, 0x65, 0x6e, 0x73, 0x65, 0x6e],
                        .. Default::default()
                   })
            ]
        });

        assert_eq!(parse(f), Ok(tag));
    }

    #[test]
    fn not() {
        let f = "(!(cn=Tim Howes))";

        let tag = Tag::ExplicitTag(ExplicitTag {
            class: TagClass::Context,
            id: 2,
            inner: Box::new(Tag::Sequence(Sequence {
                class: TagClass::Context,
                id: 3,
                inner: vec![
                   Tag::OctetString(OctetString {
                       inner: vec![0x63, 0x6e],
                       .. Default::default()
                   }),
                   Tag::OctetString(OctetString {
                       inner: vec![0x54, 0x69, 0x6d, 0x20, 0x48, 0x6f, 0x77, 0x65, 0x73],
                       .. Default::default()
                   })
                ],
            })),
        });

        assert_eq!(parse(f), Ok(tag));
    }

    #[test]
    fn and() {
        let f = "(&(a=b)(b=c)(c=d))";

        let tag = Tag::Sequence(Sequence {
            class: TagClass::Context,
            id: 0,
            inner: vec![
                Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 3,
                    inner: vec![
                       Tag::OctetString(OctetString {
                           inner: vec![0x61],
                           .. Default::default()
                       }),
                       Tag::OctetString(OctetString {
                           inner: vec![0x62],
                            .. Default::default()
                       })
                    ]
                }),
                Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 3,
                    inner: vec![
                       Tag::OctetString(OctetString {
                           inner: vec![0x62],
                           .. Default::default()
                       }),
                       Tag::OctetString(OctetString {
                           inner: vec![0x63],
                            .. Default::default()
                       })
                    ]
                }),
                Tag::Sequence(Sequence {
                    class: TagClass::Context,
                    id: 3,
                    inner: vec![
                       Tag::OctetString(OctetString {
                           inner: vec![0x63],
                           .. Default::default()
                       }),
                       Tag::OctetString(OctetString {
                           inner: vec![0x64],
                            .. Default::default()
                       })
                    ]
                }),
            ]
        });

        assert_eq!(parse(f), Ok(tag));
    }
}
