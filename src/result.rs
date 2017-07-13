use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::io;
use std::result::Result;

use controls::Control;
use protocol::LdapResultExt;

use lber::structures::Tag;

/// Common components of an LDAP operation result.
///
/// This structure faithfully replicates the components dictated by the standard,
/// and is distinctly C-like with its reliance on numeric codes for the indication
/// of outcome. It would be tempting to hide it behind an automatic `Result`-like
/// interface, but there are scenarios where this would preclude intentional
/// incorporation of error conditions into query design. Instead, the struct
/// implements helper methods, [`success()`](#method.success) and [`non_error()`]
/// (#method.non_error), which may be used for ergonomic error handling when
/// simple condition checking suffices.
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

impl Error for LdapResult {
    fn description(&self) -> &'static str {
	match self.rc {
	    0 => "success",
	    1 => "operationsError",
	    2 => "protocolError",
	    3 => "timeLimitExceeded",
	    4 => "sizeLimitExceeded",
	    5 => "compareFalse",
	    6 => "compareTrue",
	    7 => "authMethodNotSupported",
	    8 => "strongerAuthRequired",
	    10 => "referral",
	    11 => "adminLimitExceeded",
	    12 => "unavailableCriticalExtension",
	    13 => "confidentialityRequired",
	    14 => "saslBindInProgress",
	    16 => "noSuchAttribute",
	    17 => "undefinedAttributeType",
	    18 => "inappropriateMatching",
	    19 => "constraintViolation",
	    20 => "attributeOrValueExists",
	    21 => "invalidAttributeSyntax",
	    32 => "noSuchObject",
	    33 => "aliasProblem",
	    34 => "invalidDNSyntax",
	    36 => "aliasDereferencingProblem",
	    48 => "inappropriateAuthentication",
	    49 => "invalidCredentials",
	    50 => "insufficientAccessRights",
	    51 => "busy",
	    52 => "unavailable",
	    53 => "unwillingToPerform",
	    54 => "loopDetect",
	    64 => "namingViolation",
	    65 => "objectClassViolation",
	    66 => "notAllowedOnNonLeaf",
	    67 => "notAllowedOnRDN",
	    68 => "entryAlreadyExists",
	    69 => "objectClassModsProhibited",
	    71 => "affectsMultipleDSAs",
	    80 => "other",
	    88 => "abandoned",
	    _ => "unknown",
	}
    }
}

impl fmt::Display for LdapResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
	write!(f,
	    "rc={} ({}), dn: \"{}\", text: \"{}\"",
	    self.rc,
	    self.description(),
	    self.matched,
            self.text
        )
    }
}

impl LdapResult {
    /// If the result code is zero, return the instance itself wrapped
    /// in `Ok()`, otherwise wrap the instance in an `io::Error`.
    pub fn success(self) -> Result<Self, io::Error> {
        if self.rc == 0 {
            Ok(self)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self))
        }
    }

    /// If the result code is 0 or 10 (referral), return the instance
    /// itself wrapped in `Ok()`, otherwise wrap the instance in an 
    /// io::Error`.
    pub fn non_error(self) -> Result<Self, io::Error> {
        if self.rc == 0 || self.rc == 10 {
            Ok(self)
        } else {
            Err(io::Error::new(io::ErrorKind::Other, self))
        }
    }
}
