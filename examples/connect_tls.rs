use ldap3::LdapConn;

const LDAPS_SERVER: &str = "ldaps://directory.example.com:636";
const LDAP_SERVICE_USER_DN: &str = "CN=ldapuser,CN=Users,DC=example,DC=com";
const LDAP_SERVICE_USER_PW: &str = "SuperSecretPassword";

fn main() {

    let ldap = LdapConn::new(LDAPS_SERVER).expect("Failed to create handle");

    ldap.simple_bind(LDAP_SERVICE_USER_DN, LDAP_SERVICE_USER_PW).expect("Bind error");
    
}
