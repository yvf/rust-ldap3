use super::Exop;

pub const STARTTLS_OID: &'static str = "1.3.6.1.4.1.1466.20037";

/// StartTLS extended operation ([RFC 4511](https://tools.ietf.org/html/rfc4511#section-4.14)).
///
/// This operation isn't meant to be directly used by user code; it is used by
/// connection-establishment routines when the StartTLS mechanism of securing the
/// connection is requested by the user.
// "StartTLS" is the form used in the RFCs; no need to change it or rename the struct
#[cfg_attr(feature = "cargo-clippy", allow(doc_markdown))]
pub struct StartTLS;

impl From<StartTLS> for Exop {
    fn from(_s: StartTLS) -> Exop {
        Exop {
            name: Some(STARTTLS_OID.to_owned()),
            val: None,
        }
    }
}
