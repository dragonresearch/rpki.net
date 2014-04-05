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

# Clean up trailing whitespace.
{
    sub(/[ \t]+$/, "");
}

# Continuation line: strip comment, if any, then append value, if any,
# to what we had from previous line(s).
/^[^A-Z]/ {
    sub(/[ \t]*#.*$/, "");
    if (NF)
	val = val $0;
    next;
}

# Anything other than line continuation terminates the previous line,
# so if we were working on a line, we're done with it now, process it.
key {
    do_line();
}

# Non-empty line and we have no tag, this must be start of a new block.
NF && !tag {
    tag = $1;
}

# One of the tags we care about, clean up and save the data.
/^(AS-NAME|AUT-NUM|INET6NUM|INETNUM|MNT-BY|NETNAME|STATUS):/ {
    key = $1;
    sub(/^[^ \t]+:/, "");
    sub(/[ \t]*#.*$/, "");
    val = $0;
}

# Blank line and we have something, process it.
!NF && tag {
    do_block();
}

# End of file, process final data, if any.
END {
    do_line();
    do_block();
}

# Handle one line, after line icky RPSL continuation.
function do_line() {
    gsub(/[ \t]/, "", val);
    if (key && val)
	tags[key] = val;
    key = "";
    val = "";
}

# Dispatch to handle known block types, then clean up so we can start
# a new block.
function do_block() {
    if (tag == "INETNUM" || tag == "INET6NUM")
	do_prefix();
    else if (tag == "AUT-NUM")
	do_asn();
    delete tags;
    tag = "";
}

# Handle an AUT-NUM block: extract the ASN, use MNT-BY as the handle.
function do_asn() {
    sub(/^AS/, "", tags[tag]);
    if (tags["MNT-BY"] && tags[tag])
	print tags["MNT-BY"], tags[tag] >"asns.csv";
}

# Handle an INETNUM or INET6NUM block: check for the status values we
# care about, use NETNAME as the handle.
function do_prefix() {
    if (tags["STATUS"] ~ /^ASSIGNED(P[AI])$/ && tags["NETNAME"] && tags[tag])
	print tags["NETNAME"], tags[tag] >"prefixes.csv";
}
