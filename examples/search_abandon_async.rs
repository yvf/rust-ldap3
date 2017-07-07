extern crate futures;
extern crate ldap3;
extern crate tokio_core;

use std::io;
use std::result::Result;

use futures::{Future, Stream};
use ldap3::{LdapConnAsync, LdapResult, Scope};
use tokio_core::reactor::Core;

const ENTRIES_BEFORE_ABANDON: usize = 1;

fn main() {
    match do_abandon() {
        Ok(r) => println!("{:?}", r),
        Err(e) => println!("{:?}", e),
    }
}

fn do_abandon() -> Result<LdapResult, io::Error> {
    let mut core = Core::new()?;
    let handle = core.handle();
    let ldap = LdapConnAsync::new("ldap://localhost:2389", &handle)?;
    let srch = ldap
        .and_then(|ldap| {
            ldap.search(
                "ou=Places,dc=example,dc=org",
                Scope::Subtree,
                "objectClass=locality",
                vec!["l"]
        )})
        .and_then(|(mut strm, rx)| {
            let mut count = 0;
            let a_chan = strm.get_abandon_channel();
            a_chan.and_then(move |a_chan| {
                rx.map_err(|_e| io::Error::from(io::ErrorKind::Other))
                    .join(strm.for_each(move |_tag| {
                        if count == ENTRIES_BEFORE_ABANDON {
                            a_chan.send(())
                                .map_err(|_e| io::Error::new(io::ErrorKind::Other, "a_chan send"))
                        } else {
                            count += 1;
                            Ok(())
                        }
                    }))
            })
        })
        .map(|((res, _), _)| res);
    core.run(srch)
}
