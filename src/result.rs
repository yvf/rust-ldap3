use std::collections::HashSet;

use controls::Control;
use protocol::LdapResultExt;

use lber::structures::Tag;

/// Common components of an LDAP operation result.
///
/// This structure faithfully replicates the components dictated by the standard,
/// and is distinctly C-like with its reliance on numeric codes for the indication
/// of outcome. It would be tempting to hide it behind an automatic `Result`-like
/// interface, but there are scenarios where this would preclude intentional
/// incorporation of error conditions into query design.
///
/// A series of helper methods to provide idiomatic error handling is planned.
///
/// __Note__: this structure will probably be extended with the vector of
/// response controls in version 0.5.x, since controls are always part of the
/// response message.
#[derive(Clone, Debug)]
pub struct LdapResult {
    /// Result code.
    ///
    /// Generally, the value of zero indicates successful completion, but there's
    /// a number of other non-error codes arising as a result of various operations.
    /// See [Section A.1 of RFC 4511](https://tools.ietf.org/html/rfc4511#appendix-A.1).
    pub rc: u32,
    /// Matched component DN, where applicable.
    pub matched: String,
    /// Additional diagnostic text.
    pub text: String,
    /// Referrals.
    ///
    /// In the current implementation, all referrals received during a Search
    /// operation will be accumulated in this vector.
    pub refs: Vec<HashSet<String>>,
    /// Response controls.
    ///
    /// Missing and empty controls are both represented by an empty vector.
    pub ctrls: Vec<Control>,
}

#[doc(hidden)]
impl From<Tag> for LdapResult {
    fn from(t: Tag) -> LdapResult {
        <LdapResultExt as From<Tag>>::from(t).0
    }
}
