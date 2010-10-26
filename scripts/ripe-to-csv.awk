#!/usr/bin/awk -f

# Parse a WHOIS research dump and write out (just) the RPKI-relevant
# fields in myrpki-format CSV syntax.
#
# Unfortunately, unlike the ARIN and APNIC databases, the RIPE database
# doesn't really have any useful concept of an organizational handle.
# More precisely, while it has handles out the wazoo, none of them are
# useful as a reliable grouping mechanism for tracking which set of
# resources are held by a particular organization.  So, instead of being
# able to track all of an organization's resources with a single handle
# as we can in the ARIN and APNIC databases, the best we can do with the
# RIPE database is to track individual resources, each with its own
# resource handle.  Well, for prefixes -- ASN entries behave more like
# in the ARIN and APNIC databases.
#
# Feh.
#
# NB: The input data for this script is publicly available via FTP, but
# you'll have to fetch the data from RIPE yourself, and be sure to see
# the terms and conditions referenced by the data file header comments.
# 
# $Id$
#
# Copyright (C) 2009-2010  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

BEGIN {
    FS = "[ \t]*:";
    OFS = "\t";
}

{
    sub(/#.*$/, "");
    sub(/[ \t]+$/, "");
}

NF && !tag {
    tag = $1;
}

/^(as-name|aut-num|inet6num|inetnum|mnt-by|netname|status):/ {
    t = $1;
    sub(/^[^ \t]+:/, "");
    gsub(/[ \t]/, "");
    tags[t] = $0;
}

!NF && tag {
    got_one();
}

END {
    got_one();
}

function got_one() {
    if (tag == "inetnum" || tag == "inet6num")
	got_inetnum();
    else if (tag == "aut-num")
	got_aut_num();
    delete tags;
    tag = "";
}

function got_aut_num() {
    sub(/^AS/, "", tags["aut-num"]);
    print tags["mnt-by"], tags["aut-num"] >"asns.csv";
}

function got_inetnum() {
    if (tags["status"] ~ /^ASSIGNED(P[AI])?$/)
	print tags["netname"], tags[tag] >"prefixes.csv";
}
