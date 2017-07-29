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


/// Escapes an attribute value in a distinguished name (DN).
///
/// For example, a DN might be
/// `uid=test_user,ou=Users,dc=myldapdomain,dc=myorg,dc=com`, where each of
/// the fields, or "attribute values" can contain any characters, but some
/// special characters must be escaped. (space, double quote, number sign,
/// plus sign, comma, semicolon, less than, greater than and equals signs,
/// backslash, NUL)
/// 
/// If you construct a DN yourself, you have to make sure that the attribute
/// values are properly escaped.
pub fn dn_escape<'a, S: Into<Cow<'a, str>>>(lit: S) -> Cow<'a, str> {
    #[inline]
    fn needs_escape(c: u8) -> bool {
        c == b' ' || c == b'"' || c == b'#' || c == b'+' || c == b',' ||
        c == b';' || c == b'<' || c == b'=' || c == b'>' || c == b'\\' || c == 0
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
