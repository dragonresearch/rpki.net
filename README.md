# Dragon Research Labs RPKI Toolkit

This is the "rpki.net" toolkit developed and maintained primarily by
Dragon Research Labs.  It's had several other names over the years
("DRL RPKI toolkit", "ISC RPKI toolkit", etc), but it's the same
toolkit under the same BSD-style license, now moved to GitHub.

## Documentation

There's a
[pile of documentation salvaged from the old wiki](doc/)
in the doc/ subdirectory: see the README in that directory for details.

Be warned that the existing documentation is for the "old-trunk"
branch, which is not what you want to be using these days (among other
reasons, because "old-trunk" depends on obsolete third party packages
which are no longer supported by their respective authors).  We will
update the documentation for the current "master" branch as time and
other work permits.

## Signatures

All commits to this repository on or after 2016-08-07 should be
GPG-signed.

## Binary packages

QuickStart guides for RP and CA on Ubuntu Xenial are [here](doc/quickstart/README.md)

Setup on Debian Jessie is similar, other than the APT URLs (below).

Binary packages for
[Ubuntu Xenial](https://download.rpki.net/APTng/ubuntu/)
and
[Debian Jessie](https://download.rpki.net/APTng/debian/)
are available from https://download.rpki.net/APTng/.

The source packaging scripts for FreeBSD are a bit stale, someday
we'll fix that.

## Thanks

From 2006 through 2008, this work was funded by [ARIN](http://www.arin.net/).

From 2009 through 2016, this work was funded by [DHS](http://www.dhs.gov/).

Special thanks to Michael Elkins, who wrote the web GUI and generally
served as a second brain and second set of eyeballs on a long list of
thorny technical problems.
