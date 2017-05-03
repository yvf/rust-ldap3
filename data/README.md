# LDAP server for examples

This directory contains setup scripts and data files for creating
an OpenLDAP server against which example programs can be run. The scripts
expect that you have a recent-ish OpenLDAP installation on your system;
they have been tested on CentOS 7 and Ubuntu 16.04. CentOS 6, Fedora,
and recent Debian should also work.

* On Ubuntu, install `slapd` and `ldap-utils`.

* On CentOS, install `openldap-servers` and `openldap-clients`.

* On both distros, install `make`.

This setup shouldn't be used for anything serious: in the interest of
uniformity, it uses Debian-specific parameters for the config database
which just happen to work elsewhere, but would almost certainly cause
problems for anything more complex.

All scripts should be run from this directory.

* To start from a clean slate, run `make clean`.

* To create the example database and import the data, run `make db`.

* To start the database, run `./startdb.sh`.

* To stop the database, run `./stopdb.sh`.

The database server will listen on __localhost:2389__ and a Unix
domain socket __ldapi__ in the current directory.

Examples are run by invoking `cargo run --quiet --example `_`name`_.
For the file `examples/search.rs`, that would be
`cargo run --quiet --example search`.
