# $Id$

"""
Command line program to simulate behavior of the IR back-end.
"""

import glob, rpki.left_right, rpki.relaxng, getopt, sys, lxml.etree, POW, POW.pkix

# Kludge around current test setup all being PEM rather than DER format
convert_from_pem = True

class command(object):

  elements = ()

  def getopt(self, argv):
    opts, args = getopt.getopt(argv, "", [x + "=" for x in self.attributes + self.elements] + [x for x in self.booleans])
    for o, a in opts:
      o = o[2:]
      handler = getattr(self, "handle_" + o, None)
      if handler is not None:
        handler(a)
      elif o in self.booleans:
        setattr(self, o, True)
      else:
        assert o in self.attributes
        setattr(self, o, a)
    return args

  def process(self, msg, argv):
    argv = self.getopt(argv)
    msg.append(self)
    return argv

  def handle_action(self, arg):
    self.action = arg
    self.type = "query"

  def handle_peer_ta(self, arg):
    self.peer_ta = read_cert(arg)

def read_cert(filename):
  f = open(filename, "r")
  der = f.read()
  f.close()
  if convert_from_pem:
    der = POW.pemRead(POW.X509_CERTIFICATE, der).derWrite()
  cert = POW.pkix.Certificate()
  cert.fromString(der)
  return cert

class self(command, rpki.left_right.self_elt):

  elements = ("extension_preference",)

  def handle_extension_preference(self, arg):
    k,v = arg.split("=", 1)
    pref = rpki.left_right.extension_preference_elt()
    pref.name = k
    pref.value = v
    self.prefs.append(pref)

class bsc(command, rpki.left_right.bsc_elt):
  elements = ('signing_cert',)

  def handle_signing_cert(self, arg):
    self.signing_cert.append(read_cert(arg))

class parent(command, rpki.left_right.parent_elt):
  elements = ("peer_ta",)

class child(command, rpki.left_right.child_elt):
  elements = ("peer_ta",)

class repository(command, rpki.left_right.repository_elt):
  elements = ("peer_ta",)

class route_origin(command, rpki.left_right.route_origin_elt):

  def handle_asn(self, arg):
    self.asn = long(arg)

  def handle_ipv4(self, arg):
    self.ipv4 = resource_set.resource_set_ipv4(arg)

  def handle_ipv6(self, arg):
    self.ipv6 = resource_set.resource_set_ipv6(arg)

dispatch = dict((x.__name__, x) for x in (self, bsc, parent, child, repository, route_origin))

def usage():
  print "Usage:", sys.argv[0]
  for k,v in dispatch.iteritems():
    print " ", k, " ".join(["--" + x + "=" for x in v.attributes + v.elements]), " ".join(["--" + x for x in v.booleans])
  sys.exit(1)

rng = rpki.relaxng.RelaxNG("left-right-schema.rng")
msg = rpki.left_right.msg()

argv = sys.argv[1:]

if not argv:
  usage()
else:
  while argv:
    try:
      cmd = dispatch[argv[0]]()
    except KeyError:
      usage()
    argv = cmd.process(msg, argv[1:])

if msg:
  elt = msg.toXML()
  xml = lxml.etree.tostring(elt, pretty_print=True, encoding="us-ascii", xml_declaration=True)
  try:
    rng.assertValid(elt)
  except lxml.etree.DocumentInvalid:
    print "Generated request document doesn't pass schema check:"
    print xml
    sys.exit(1)
  print xml
