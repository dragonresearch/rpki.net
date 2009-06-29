# $Id$

"""
Generate .dot description of a certificate tree.
"""

import POW, sys, glob, os

class x509(object):

  ski = None
  aki = None

  show_file    = False
  show_ski     = False
  show_aki     = False
  show_issuer  = True
  show_subject = True

  cn_only      = True

  subjects = {}

  def __init__(self, filename):

    while filename.startswith("./"):
      filename = filename[2:]

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

    self.subject = self.canonize(self.pow.getSubject())
    self.issuer  = self.canonize(self.pow.getIssuer())

    if self.subject in self.subjects:
      self.subjects[self.subject].append(self)
    else:
      self.subjects[self.subject] = [self]

  def canonize(self, name):

    if self.cn_only and len(name) == 1 and name[0][0] == "CN":
      return name[0][1]
    else:
      return name

  def set_node(self, node):

    self.node = node

  def dot(self):

    label = []

    if self.show_issuer:
      label.append(("Issuer", self.issuer))

    if self.show_subject:
      label.append(("Subject", self.subject))

    if self.show_file:
      label.append(("File", self.filename))

    if self.show_aki:
      label.append(("AKI", self.aki))

    if self.show_ski:
      label.append(("SKI", self.ski))

    print "#", repr(label)

    if len(label) > 1:
      print '%s [shape = record, label = "{%s}"];' % (self.node, "|".join("{%s|%s}" % (x, y) for x, y in label if y is not None))
    else:
      print '%s [label = "%s"];' % (self.node, label[0][1])

    for issuer in self.subjects.get(self.issuer, ()):

      if issuer is self:
        print "# Issuer is self"
        issuer = None

      if issuer is not None and self.aki is not None and self.ski is not None and self.aki == self.ski:
        print "# Self-signed"
        issuer = None

      if issuer is not None and self.aki is not None and issuer.ski is not None and self.aki != issuer.ski:
        print "# AKI does not match issuer SKI"
        issuer = None

      if issuer is not None:
        print "%s -> %s;" % (issuer.node, self.node)

    print

certs = []

for topdir in sys.argv[1:] or ["."]:
  for dirpath, dirnames, filenames in os.walk(topdir):
    certs += [x509(dirpath + "/" + filename) for filename in filenames if filename.endswith(".cer")]

for i, cert in enumerate(certs):
  cert.set_node("cert_%d" % i)

print """\
digraph certificates {

rotate = 90;
#size = "11,8.5";
splines = true;
ratio = fill;

"""

for cert in certs:
  cert.dot()

print "}"
