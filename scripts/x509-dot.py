# $Id$

"""
Generate .dot description of a certificate tree.
"""

import POW, sys, glob, os

class x509(object):

  ski = None
  aki = None

  def __init__(self, filename):

    self.filename = filename

    f = open(filename, "rb")
    text = f.read()
    f.close()

    if text.find("-----BEGIN") >= 0:
      self.pow = POW.pemRead(POW.X509_CERTIFICATE, text)
    else:
      self.pow = POW.derRead(POW.X509_CERTIFICATE, text)

    self.extensions = dict((e[0], e[2]) for e in (self.pow.getExtension(i) for i in xrange(self.pow.countExtensions())))

    if "subjectKeyIdentifier" in self.extensions:
      self.ski = ":".join(["%02X" % ord(i) for i in self.extensions.get("subjectKeyIdentifier")[1:]])

    if "authorityKeyIdentifier" in self.extensions:
      self.aki = ":".join(["%02X" % ord(i) for i in self.extensions.get("authorityKeyIdentifier")[3:]])

    self.subject = self.pow.getSubject()
    self.issuer  = self.pow.getIssuer()

  def set_node(self, node):

    self.node = node

  def dot(self):

    print '%s [shape = record, label = "{File %s|Issuer %s|Subject %s|AKI %s|SKI %s}"];' % (self.node, self.filename, self.issuer, self.subject, self.aki, self.ski)

    issuer = subjects.get(self.issuer)

    if issuer is self:
      issuer = None

    if issuer is not None and self.aki is not None and issuer.ski is not None and self.aki != issuer.ski:
      issuer = None

    if issuer is not None:
      print "%s -> %s;" % (issuer.node, self.node)

    print

certs = []

for topdir in sys.argv[1:] or ["."]:
  for dirpath, dirnames, filenames in os.walk(topdir):
    certs += [x509(dirpath + "/" + filename) for filename in filenames if filename.endswith(".cer")]

for i in xrange(len(certs)):
  certs[i].set_node("cert_%d" % i)

subjects = dict((x.subject, x) for x in certs)

print """\
digraph certificates {

rotate = 90; size = "11,8.5";
splines = true;
ratio = fill;

"""

for cert in certs:
  cert.dot()

print "}"
