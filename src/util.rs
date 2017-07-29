use std::borrow::Cow;

/// Escape a filter literal.
///
/// Literal values appearing in an LDAP filter can contain any character,
/// but some characters (parentheses, asterisk, backslash, NUL) must be
/// escaped in the filter's string representation. This function does the
/// escaping.
///
/// The argument, `lit`, can be owned or borrowed. The function doesn't
/// allocate the return value unless there's need to escape the input.
pub fn ldap_escape<'a, S: Into<Cow<'a, str>>>(lit: S) -> Cow<'a, str> {
    #[inline]
    fn needs_escape(c: u8) -> bool {
        c == b'\\' || c == b'*' || c == b'(' || c == b')' || c == 0
    }

    #[inline]
    fn xdigit(c: u8) -> u8 {
        c + if c < 10 { b'0' } else { b'a' - 10 }
    }

    let lit = lit.into();
    let mut output = None;
    for (i, &c) in lit.as_bytes().iter().enumerate() {
        if needs_escape(c) {
            if output.is_none() {
                output = Some(Vec::with_capacity(lit.len() + 12)); // guess: up to 4 escaped chars
                output.as_mut().unwrap().extend(lit[..i].as_bytes());
            }
            let output = output.as_mut().unwrap();
            output.push(b'\\');
            output.push(xdigit(c >> 4));
            output.push(xdigit(c & 0xF));
        } else if let Some(ref mut output) = output {
            output.push(c);
        }
    }
    if let Some(output) = output {
        // unchecked conversion is safe here: we receive a valid
        // UTF-8 value, by definition, and only replace single ASCII
        // bytes with ASCII byte sequences
        Cow::Owned(unsafe { String::from_utf8_unchecked(output) })
    } else {
        lit.into()
    }
}

/// Escape an attribute value in a relative distinguished name (RDN).
///
/// When a literal string is used to represent an attribute value in an RDN,
/// some of it characters might need to be escaped according to the rules
/// of [RFC 4514](https://tools.ietf.org/html/rfc4514).
///
/// The function is named `dn_escape()` instead of `rdn_escape()` because of
/// a long-standing association of its intended use with the handling of DNs.
///
/// The argument, `val`, can be owned or borrowed. The function doesn't
/// allocate the return value unless there's need to escape the input.
pub fn dn_escape<'a, S: Into<Cow<'a, str>>>(val: S) -> Cow<'a, str> {
    #[inline]
    fn always_escape(c: u8) -> bool {
        c == b'"' || c == b'+' || c == b',' || c == b';' ||
        c == b'<' || c == b'=' || c == b'>' || c == b'\\' ||
        c == 0
    }

    #[inline]
    fn escape_leading(c: u8) -> bool {
        c == b' ' || c == b'#'
    }

    #[inline]
    fn escape_trailing(c: u8) -> bool {
        c == b' '
    }

    #[inline]
    fn xdigit(c: u8) -> u8 {
        c + if c < 10 { b'0' } else { b'a' - 10 }
    }

    let val = val.into();
    let mut output = None;
    for (i, &c) in val.as_bytes().iter().enumerate() {
        if always_escape(c) || i == 0 && escape_leading(c) || i + 1 == val.len() && escape_trailing(c) {
            if output.is_none() {
                output = Some(Vec::with_capacity(val.len() + 12)); // guess: up to 4 escaped chars
                output.as_mut().unwrap().extend(val[..i].as_bytes());
            }
            let output = output.as_mut().unwrap();
            output.push(b'\\');
            output.push(xdigit(c >> 4));
            output.push(xdigit(c & 0xF));
        } else if let Some(ref mut output) = output {
            output.push(c);
        }
    }
    if let Some(output) = output {
        // see the rationale for the same construct in ldap_escape()
        Cow::Owned(unsafe { String::from_utf8_unchecked(output) })
    } else {
        val.into()
    }
}

#[cfg(test)]
mod test {
    use super::dn_escape;

    #[test]
    fn dn_esc_leading_space() {
        assert_eq!(dn_escape(" foo"), "\\20foo");
    }

    #[test]
    fn dn_esc_trailing_space() {
        assert_eq!(dn_escape("foo "), "foo\\20");
    }

    #[test]
    fn dn_esc_inner_space() {
        assert_eq!(dn_escape("f o o"), "f o o");
    }

    #[test]
    fn dn_esc_single_space() {
        assert_eq!(dn_escape(" "), "\\20");
    }

    #[test]
    fn dn_esc_two_spaces() {
        assert_eq!(dn_escape("  "), "\\20\\20");
    }

    #[test]
    fn dn_esc_three_spaces() {
        assert_eq!(dn_escape("   "), "\\20 \\20");
    }

    #[test]
    fn dn_esc_leading_hash() {
        assert_eq!(dn_escape("#rust"), "\\23rust");
    }
}
