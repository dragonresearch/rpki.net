"""
Generate IRR route and route6 objects from ROAs.

The only required argument is the name of a directory tree containing
the validated outpt of an rcynic run.  If you follow the default
naming scheme this will be /some/where/rcynic-data/authenticated.

If given the --output option, the argument to that option will be
interpreted as the name of a directory (which will be created if it
does not already exist) in which to write route and route6 objects,
one object per file.

If not given the --output option, this program will write all the
route and route6 objects to standard output, separated by blank lines.
In this mode, if also given the --email option, the program will
generate a fake RFC (2)822 header suitable for piping all of this into
irr_rpsl_submit.

The other options allow control of several required fields, to let you
change email addresses and so forth if the defaults values aren't
right.


$Id$

Copyright (C) 2010-2012  Internet Systems Consortium ("ISC")

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

import os
import socket
import sys
import getopt
import errno
import time
import rpki.x509
import rpki.ipaddrs

class route_virtual(object):
  """
  All the interesting parts of a route object, as a virtual class.
  """

  def __init__(self, uri, asnum, date, asn1):
    assert len(asn1[0]) <= self.addr_type.bits
    x = 0L
    for y in asn1[0]:
      x = (x << 1) | y
    x <<= (self.addr_type.bits - len(asn1[0]))
    self.uri = uri
    self.asn = asnum
    self.date = date
    self.prefix = self.addr_type(x)
    self.prefixlen = len(asn1[0])
    self.max_prefixlen = self.prefixlen if asn1[1] is None else asn1[1]

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
    lines = (
      "%-14s%s/%s" % (self.label, self.prefix, self.prefixlen),
      "descr:        %s/%s-%s" % (self.prefix, self.prefixlen, self.max_prefixlen),
      "origin:       AS%d" % self.asn,
      "notify:       %s" % irr_notify,
      "mnt-by:       %s" % irr_mnt_by,
      "changed:      %s %s" % (irr_changed_by, self.date),
      "source:       %s" % irr_source,
      "override:     %s" % password if password is not None else None,
      "")
    return "\n".join(line for line in lines if line is not None)

  def write(self, output_directory):
    name = "%s-%s-%s-AS%d-%s" % (self.prefix, self.prefixlen, self.max_prefixlen, self.asn, self.date)
    open(os.path.join(output_directory, name), "w").write(str(self))

class route_ipv4(route_virtual):
  """
  IPv4 route object.
  """

  addr_type = rpki.ipaddrs.v4addr
  label = "route:"

class route_ipv6(route_virtual):
  """
  IPv6 route object.
  """

  addr_type = rpki.ipaddrs.v6addr
  label = "route6:"

afi_map = { "\x00\x01" : route_ipv4, "\x00\x02" : route_ipv6 }

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
          version, asnum, asn1 = roa.extract().get()
          assert version == 0, "ROA version is %d, expected 0" % version
          notBefore = rpki.x509.X509(POW = roa.get_POW().certs()[0]).getNotBefore()
          for afi, addrs in asn1:
            for addr in addrs:
              self.append(afi_map[afi](uri, asnum, notBefore.strftime("%Y%m%d"), addr))
    self.sort()
    for i in xrange(len(self) - 2, -1, -1):
      if self[i] == self[i + 1]:
        del self[i + 1]

# Main program

whoami = "%s@%s" % (os.getlogin(), socket.gethostname())

irr_notify     = whoami
irr_changed_by = whoami
irr_mnt_by     = "MAINT-RPKI"
irr_source     = "RPKI"
irr_from       = whoami
output         = None
email          = False
password       = None

options = ["changed_by=", "email", "from=", "help", "mnt_by=",
           "notify=", "output=", "password=", "source="]

def usage(code = 1):
  f = sys.stderr if code else sys.stdout
  f.write("Usage: %s [options] rcynic-data/authenticated\n\nOptions:\n" % sys.argv[0])
  for opt in options:
    f.write("  --" + ((opt[:-1] + " argument") if "=" in opt else opt) + "\n")
  f.write(__doc__)
  sys.exit(code)

opts, argv = getopt.getopt(sys.argv[1:], "c:ef:hm:n:o:p:s:?", options)
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    usage(0)
  elif o in ("-c", "--changed_by"):
    irr_changed_by = a
  elif o in ("-e", "--email"):
    email = True
  elif o in ("-f", "--from"):
    irr_from = a
  elif o in ("-m", "--mnt_by"):
    irr_mnt_by = a
  elif o in ("-n", "--notify"):
    irr_notify = a
  elif o in ("-o", "--output"):
    output = a
  elif o in ("-p", "--password"):
    password = a
  elif o in ("-s", "--source"):
    source = a
  else:
    usage()

if len(argv) != 1 or not os.path.isdir(argv[0]):
  usage()

routes = route_list(argv[0])

if output:
  try:
    os.makedirs(output)
  except OSError, e:
    if e.errno != errno.EEXIST:
      raise
  for r in routes:
    r.write(output)
else:
  if email:
    print "From", irr_from
    print "Date:", time.strftime("%d %b %Y %T %z")
    print "From:", irr_from
    print "Subject: Fake email header to make irr_rpsl_submit happy"
    print "Message-Id: <%s.%s@%s>" % (os.getpid(), time.time(), socket.gethostname())
    print
  for r in routes:
    print r
