extern crate ldap3;

use ldap3::{LdapConn, Scope};
use ldap3::controls::{Control, PagedResults};
use ldap3::controls::{parse_control, types};

fn main() {
    let ldap = LdapConn::new("ldap://localhost:2389").expect("ldap handle");
    let mut cookie = Vec::new();
    let mut count = 0;
    let mut continue_search = true;
    while continue_search {
        let mut strm = ldap
            .with_controls(vec![PagedResults { size: 500, cookie: cookie.clone() }.into()])
            .streaming_search(
                "ou=Places,dc=example,dc=org",
                Scope::Subtree,
                "objectClass=locality",
                vec!["l"]
            ).expect("stream");
        while let Ok(Some(_r)) = strm.next() {
            count += 1;
        }
        let (res, ctrls) = strm.result().expect("result");
        continue_search = false;
        if res.rc == 0 {
            for ctrl in ctrls {
                if let Control(Some(types::PagedResults), ref raw) = ctrl {
                    if let Some(ref v) = raw.val {
                        let pr: PagedResults = parse_control(v);
                        if !pr.cookie.is_empty() {
                            cookie = pr.cookie.clone();
                            continue_search = true;
                        }
                    }
                }
            }
        }
    }
    println!("Entries: {}", count);
}
