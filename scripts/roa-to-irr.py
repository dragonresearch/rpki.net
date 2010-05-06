"""
Generate IRR route and route6 objects from ROAs.

$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

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

import os, socket, sys, getopt, errno, rpki.x509, rpki.ipaddrs

class route_virtual(object):
  """
  All the interesting parts of a route object, as a virtual class.
  """

  def __init__(self, gski, uri, asnum, date, asn1):
    assert len(asn1[0]) <= self.addr_type.bits
    x = 0L
    for y in asn1[0]:
      x = (x << 1) | y
    x <<= (self.addr_type.bits - len(asn1[0]))
    self.gski = gski
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
    return "".join((
      ("%-14s%s/%s\n" % (self.label, self.prefix, self.prefixlen)),
      ("descr:        %s\n" % self.uri),
      ("origin:       AS%d\n" % self.asn),
      ("notify:       %s\n" % irr_notify),
      ("mnt-by:       %s\n" % irr_mnt_by),
      ("changed:      %s %s\n" % (irr_changed_by, self.date)),
      ("source:       %s\n" % irr_source),
      ("comment:      %s/%s-%s\n" % (self.prefix, self.prefixlen, self.max_prefixlen))))

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
          gski = f[:-4]
          path = os.path.join(root, f)
          uri = "rsync://" + path[len(rcynic_dir):].lstrip("/")
          roa = rpki.x509.ROA(DER_file = path)
          version, asnum, asn1 = roa.extract().get()
          assert version == 0, "ROA version is %d, expected 0" % version
          notBefore = rpki.x509.X509(POW = roa.get_POW().certs()[0]).getNotBefore()
          for afi, addrs in asn1:
            for addr in addrs:
              self.append(afi_map[afi](gski, uri, asnum, notBefore.strftime("%Y%m%d"), addr))
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
output         = None

options = ["changed_by=", "help", "mnt_by=", "notify=", "output=", "source="]

def usage(code = 1):
  f = sys.stderr if code else sys.stdout
  f.write("Usage: %s [options] rcynic-data/authenticated\n\nOptions:\n" % sys.argv[0])
  for opt in options:
    f.write("  --" + (opt[:-1] if "=" in opt else opt) + "\n")
  f.write(__doc__)
  sys.exit(code)

opts, argv = getopt.getopt(sys.argv[1:], "c:hm:n:o:s:?", options)
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--changed_by"):
    irr_changed_by = a
  elif o in ("-m", "--mnt_by"):
    irr_mnt_by = a
  elif o in ("-n", "--notify"):
    irr_notify = a
  elif o in ("-o", "--output"):
    output = a
  elif o in ("-s", "--source"):
    source = a
  else:
    usage()

if len(argv) != 1 or not os.path.isdir(argv[0]):
  usage()

routes = route_list("/u/sra/rpki/subvert-rpki.hactrn.net/rcynic/rcynic-data/authenticated")

if output:
  try:
    os.makedirs(output)
  except OSError, e:
    if e.errno != errno.EEXIST:
      raise
  for r in routes:
    open(os.path.join(output, r.gski), "w").write(str(r))
else:
  for r in routes:
    print r
