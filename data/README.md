# LDAP server for examples

This directory contains setup scripts and data files for creating
an OpenLDAP server against which example programs can be run. The scripts
expect that you have a recent-ish OpenLDAP installation on your system;
you should also make sure that `slapadd` and `slapd` are in your `$PATH`.

The scripts were originally tested on CentOS 7 and Ubuntu 16.04. Later
Ubuntu releases should behave the same. Following the lead of its parent,
RHEL, CentOS 8 no longer includes the OpenLDAP server. There, you can
use the packages provided by the [LTB project](https://ltb-project.org/download.html),
which also has the latest OpenLDAP for Debian and Ubuntu.

* On Ubuntu, install `slapd` and `ldap-utils`.

* On CentOS 7, install `openldap-servers` and `openldap-clients`.

* On CentOS 8, configure the [LTB yum repository](https://www.ltb-project.org/documentation/openldap-rpm.html)
  and install `openldap-ltb`.

* Whatever the distro, install `make`.

This setup shouldn't be used for anything serious: in the interest of
uniformity, it uses Debian-specific parameters for the config database
which just happen to work elsewhere, but would almost certainly cause
problems for anything more complex.

All scripts should be run from this directory.

* To start from a clean slate, run `make clean`.

* To create the example database and import the data, run `make db`.

* To start the database, run `./startdb.sh`. Additional arguments will be
  passed to `slapd`.

* To stop the database, run `./stopdb.sh`.

The database server will listen on __localhost:2389__ (ldap), __localhost:2636__ (ldaps),
and a Unix domain socket __ldapi__ in the current directory. Setting `$LDAP3_EXAMPLE_SERVER`
to a hostname or IP address will use that instead of __localhost__.

Examples are run by invoking `cargo run --quiet --example`_`name`_.
For the file `examples/bind_sync.rs`, that would be
`cargo run --quiet --example bind_sync`.
