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
# This is an AWK script rather than a Python script because it is a
# fairly simple stream parser that has to process a ridiculous amount
# of text.  AWK turns out to be significantly faster for this.
#
# There are a few known screw cases in RPSL format that this script
# doesn't attempt to handle, so if you just can't resist using
# newlines between the begin and end addresses of an IPv4 address
# range, this script will not understand your WHOIS entry.  So don't.
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

# On input, ":" is the most useful delimiter
# On output, we want tab-delimited text.
BEGIN {
    FS = "[ \t]*:";
    OFS = "\t";
}

# Clean up comments and trailing whitespace; skip lines that are empty
# after cleanup.  If we were attempting to handle line continuation,
# this is where we'd start.
!/^$/ {
    sub(/#.*$/, "");
    sub(/[ \t]+$/, "");
    if (!NF)
	next;
}

# Non-empty line and we have no tag, must be start of a new block.
NF && !tag {
    tag = $1;
}

# One of the tags we care about, clean up and save the data.
/^(AS-NAME|AUT-NUM|INET6NUM|INETNUM|MNT-BY|NETNAME|STATUS):/ {
    t = $1;
    sub(/^[^ \t]+:/, "");
    gsub(/[ \t]/, "");
    tags[t] = $0;
}

# Blank line and we have something, process it.
!NF && tag {
    got_one();
}

# End of file, process last entry, if any.
END {
    got_one();
}

# Dispatch to handle known block types, then clean up so we can start
# a new block.
function got_one() {
    if (tag == "INETNUM" || tag == "INET6NUM")
	got_inetnum();
    else if (tag == "AUT-NUM")
	got_aut_num();
    delete tags;
    tag = "";
}

# Handle an AUT-NUM block: extract the ASN, use MNT-BY as the handle.
function got_aut_num() {
    sub(/^AS/, "", tags[tag]);
    if (tags["MNT-BY"] && tags[tag])
	print tags["MNT-BY"], tags[tag] >"asns.csv";
}

# Handle an INETNUM or INET6NUM block: check for the status values we
# care about, use NETNAME as the handle.
function got_inetnum() {
    if (tags["STATUS"] ~ /^ASSIGNED(P[AI])?$/ && tags["NETNAME"] && tags[tag])
	print tags["NETNAME"], tags[tag] >"prefixes.csv";
}
