extern crate futures;
extern crate ldap3;
extern crate tokio_core;

use std::io;
use std::result::Result;

use futures::{Future, IntoFuture, Stream};
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
            ldap.streaming_search(
                "ou=Places,dc=example,dc=org",
                Scope::Subtree,
                "objectClass=locality",
                vec!["l"]
        )})
        .and_then(|mut strm| {
            let mut count = 0;
            let rx = strm.get_result_rx().into_future();
            let a_chan = strm.get_abandon_channel().into_future();
            a_chan.and_then(move |a_chan| rx.and_then(move |rx|
                rx.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                    .join(strm.for_each(move |_tag|
                        if count == ENTRIES_BEFORE_ABANDON {
                            a_chan.unbounded_send(())
                                .map_err(|_e| io::Error::new(io::ErrorKind::Other, "a_chan send"))
                        } else {
                            count += 1;
                            Ok(())
                        }
                ))
            ))
        })
        .map(|(res, _)| res);
    core.run(srch)
}
