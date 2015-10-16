# $Id$
# 
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2010--2012  Internet Systems Consortium ("ISC")
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Generate IRR route and route6 objects from ROAs.
"""

import os
import sys
import argparse
import errno

import rpki.x509

from socket     import gethostname
from textwrap   import dedent
from time       import time, strftime, gmtime, asctime

args = None

class route(object):
  """
  Interesting parts of a route object.
  """

  def __init__(self, label, uri, asnum, date, prefix, prefixlen, max_prefixlen):
    self.label = label
    self.uri = uri
    self.asn = asnum
    self.date = date
    self.prefix = prefix
    self.prefixlen = prefixlen
    self.max_prefixlen = self.prefixlen if max_prefixlen is None else max_prefixlen

  def __cmp__(self, other):
    result = cmp(self.asn, other.asn)
    if result == 0:
      result = cmp(self.prefix, other.prefix)
    if result == 0:
      result = cmp(self.prefixlen, other.prefixlen)
    if result == 0:
      result = cmp(self.max_prefixlen, other.max_prefixlen)
    if result == 0:
      result = cmp(self.date, other.date)
    return result

  def __str__(self):
    lines = "\n" if args.email else ""
    lines += dedent('''\
      {self.label:<14s}{self.prefix}/{self.prefixlen}
      descr:        {self.prefix}/{self.prefixlen}-{self.max_prefixlen}
      origin:       AS{self.asn:d}
      notify:       {args.notify}
      mnt-by:       {args.mnt_by}
      changed:      {args.changed_by} {self.date}
      source:       {args.source}
      ''').format(self = self, args = args)
    if args.password is not None:
      lines += "override:     {}\n".format(args.password)
    return lines

  def write(self, output_directory):
    name = "{0.prefix}-{0.prefixlen}-{0.max_prefixlen}-AS{0.asn:d}-{0.date}".format(self)
    with open(os.path.join(output_directory, name), "w") as f:
      f.write(str(self))


class route_list(list):
  """
  A list of route objects.
  """

  def __init__(self, rcynic_dir):
    for root, dirs, files in os.walk(rcynic_dir):
      for f in files:
        if f.endswith(".roa"):
          path = os.path.join(root, f)
          uri = "rsync://" + path[len(rcynic_dir):].lstrip("/")
          roa = rpki.x509.ROA(DER_file = path)
          roa.extract()
          assert roa.get_POW().getVersion() == 0, "ROA version is {:d}, expected 0".format(roa.get_POW().getVersion())
          asnum = roa.get_POW().getASID()
          notBefore = roa.get_POW().certs()[0].getNotBefore().strftime("%Y%m%d")
          v4, v6 = roa.get_POW().getPrefixes()
          if v4 is not None:
            for prefix, prefixlen, max_prefixlen in v4:
              self.append(route("route:", uri, asnum, notBefore, prefix, prefixlen, max_prefixlen))
          if v6 is not None:
            for prefix, prefixlen, max_prefixlen in v6:
              self.append(route("route6:", uri, asnum, notBefore, prefix, prefixlen, max_prefixlen))
    self.sort()
    for i in xrange(len(self) - 2, -1, -1):
      if self[i] == self[i + 1]:
        del self[i + 1]

def email_header(f):
  if args.email:
    now = time()
    f.write(dedent('''\
      From {from_} {ctime}
      Date: {date}
      From: {from_}
      Subject: Fake email header to make irr_rpsl_submit happy
      Message-Id: <{pid}.{seconds}@{hostname}>
      ''').format(from_    = args.from_,
                  ctime    = asctime(gmtime(now)),
                  date     = strftime("%d %b %Y %T %z", gmtime(now)),
                  pid      = os.getpid(),
                  seconds  = now,
                  hostname = gethostname()))

def main():

  global args
  whoami = "{}@{}".format(os.getlogin(), gethostname())

  parser = argparse.ArgumentParser(description = __doc__)
  parser.add_argument("-c", "--changed_by",             default = whoami,               help = "override \"changed:\" value")
  parser.add_argument("-f", "--from", dest="from_",     default = whoami,               help = "override \"from:\" header when using --email")
  parser.add_argument("-m", "--mnt_by",                 default = "MAINT-RPKI",         help = "override \"mnt-by:\" value")
  parser.add_argument("-n", "--notify",                 default = whoami,               help = "override \"notify:\" value")
  parser.add_argument("-p", "--password",                                               help = "specify \"override:\" password")
  parser.add_argument("-s", "--source",                 default = "RPKI",               help = "override \"source:\" value")
  group = parser.add_mutually_exclusive_group()
  group.add_argument("-e", "--email",                   action = "store_true",          help = "generate fake RFC 822 header suitable for piping to irr_rpsl_submit")
  group.add_argument("-d", "--output-directory",                                        help = "write route and route6 objects to directory OUTPUT, one object per file")
  parser.add_argument("authenticated_directory",                                        help = "directory tree containing authenticated rcynic output")
  args = parser.parse_args()

  if not os.path.isdir(args.authenticated_directory):
    sys.exit('"{}" is not a directory'.format(args.authenticated_directory))

  routes = route_list(args.authenticated_directory)

  if args.output_directory:
    if not os.path.isdir(args.output_directory):
      os.makedirs(args.output_directory)
    for r in routes:
      r.write(args.output_directory)
  else:
    email_header(sys.stdout)
    for r in routes:
      sys.stdout.write(str(r))

if __name__ == "__main__":
  main()
