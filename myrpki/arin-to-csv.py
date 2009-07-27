"""
Parse a WHOIS research dump and write out (just) the RPKI-relevant
fields in myrpki-format CSV syntax.

NB: The input data for this script comes from ARIN under an agreement
that allows research use but forbids redistribution, so if you think
you need a copy of the data, please talk to ARIN about it, not us.

$Id$

Copyright (C) 2009  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import gzip, csv, myrpki, rpki.resource_set, rpki.ipaddrs, rpki.sundial

class Handle(object):

    want_tags = ()

    debug = True

    def set(self, tag, val):
        if tag in self.want_tags:
            setattr(self, tag, "".join(val.split(" ")))

    def check(self):
        for tag in self.want_tags:
            if not hasattr(self, tag):
                return False
        if self.debug:
            print repr(self)
        return True

class ASHandle(Handle):

    want_tags = ("ASHandle", "ASNumber", "OrgID")

    def __repr__(self):
        return "<%s %s.%s %s>" % (self.__class__.__name__,
                                  self.OrgID, self.ASHandle, self.ASNumber)

    def finish(self, ctx):
        if self.check():
            ctx.asns.writerow((self.OrgID, self.ASNumber))
            ctx.orgids.add(self.OrgID)

class NetHandle(Handle):

    NetType = None
    range_type = rpki.resource_set.resource_range_ipv4
    addr_type = rpki.ipaddrs.v4addr

    want_tags = ("NetHandle", "NetRange", "NetType", "OrgID")
    useful_types = ("allocation", "assignment")

    def set(self, tag, val):
        Handle.set(self, tag, val)
        if tag == "NetRange":
            min, sep, max = self.NetRange.partition("-")
            self.Prefix = self.range_type(self.addr_type(min),
                                          self.addr_type(max))

    def finish(self, ctx):
        if self.NetType in self.useful_types and self.check():
            if str(self.Prefix).find("/") >= 0:
                ctx.prefixes.writerow((self.OrgID, self.Prefix))
                ctx.orgids.add(self.OrgID)
            else:
                print "Not a prefix: %r" % self

    def __repr__(self):
        return "<%s %s.%s %s %s>" % (self.__class__.__name__,
                                     self.OrgID, self.NetHandle,
                                     self.NetType, self.Prefix)
class V6NetHandle(NetHandle):

    range_type = rpki.resource_set.resource_range_ipv6
    addr_type = rpki.ipaddrs.v6addr

    want_tags = ("V6NetHandle", "NetRange", "NetType", "OrgID")

    def __repr__(self):
        return "<%s %s.%s %s %s>" % (self.__class__.__name__,
                                     self.OrgID, self.V6NetHandle,
                                     self.NetType, self.NetRange)

types = {
    "ASHandle"    : ASHandle,
    "NetHandle"   : NetHandle,
    "V6NetHandle" : V6NetHandle }

def parseline(line):
    tag, sep, val = line.partition(":")
    assert sep, "Couldn't find separator in %r" % line
    return tag.strip(), val.strip()

class gctx(object):

    def csvout(self, fn):
        return csv.writer(open(fn, "w"), dialect = myrpki.csv_dialect)

    def __init__(self):
        self.asns = self.csvout("asns.csv")
        self.prefixes = self.csvout("prefixes.csv")
        self.children = self.cvsout("children.csv")
        self.orgids = set()

    def finish(self):
        expires = rpki.sundial.now() + rpki.sundial.timedelta(years = 1)
        self.children.writerows((org, expires, "children/%s.ta.cer" % org)
                                for orgid in self.orgids)

def main():
    f = gzip.open("arin_db.txt.gz")
    cur = None
    ctx = gctx()
    for line in f:
        line = line.expandtabs().strip()
        if not line:
            if cur:
                cur.finish(ctx)
            cur = None
        elif not line.startswith("#"):
            tag, val = parseline(line)
            if cur is None:
                cur = types[tag]() if tag in types else False
            if cur:
                cur.set(tag, val)
    if cur:
        cur.finish(ctx)
    ctx.finish()

main()
