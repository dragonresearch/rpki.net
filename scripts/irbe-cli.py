# $Id$

"""
Command line program to simulate behavior of the IR back-end.
"""

import glob, rpki.left_right, rpki.relaxng, getopt, sys, lxml.etree

class command(object):

  booleans = ()

  def getopt(self, argv):
    opts, args = getopt.getopt(argv, "", [x + "=" for x in self.pdu.attributes] + [x for x in self.pdu.booleans])
    for o, a in opts:
      o = o[2:]
      handler = getattr(self, o, None)
      if handler is not None:
        handler(a)
      elif o in self.pdu.booleans:
        setattr(self.pdu, o, True)
      else:
        assert o in self.pdu.attributes
        setattr(self.pdu, o, a)
    return args

  def process(self, msg, argv):
    argv = self.getopt(argv)
    msg.append(self.pdu)
    return argv

  def action(self, arg):
    self.pdu.action = arg
    self.pdu.type = "query"

  def peer_ta(self, arg):
    self.pdu.peer_ta = read_cert(arg)

class self(command):

  def __init__(self):
    self.pdu = rpki.left_right.self_elt()

  def extension(self, arg):
    kv = arg.split(":", 1)
    self.pdu.extensions[k] = v

class bsc(command):

  def __init__(self):
    self.pdu = rpki.left_right.bsc_elt()

  def signing_cert(self, arg):
    self.pdu.signing_cert.append(read_cert(arg))

class parent(command):

  def __init__(self):
    self.pdu = rpki.left_right.parent_elt()

class child(command):

  def __init__(self):
    self.pdu = rpki.left_right.child_elt()

class repository(command):

  def __init__(self):
    self.pdu = rpki.left_right.repository_elt()

class route_origin(command):

  def __init__(self):
    self.pdu = rpki.left_right.route_origin_elt()

  def asn(self, arg):
    self.pdu.asn = long(arg)

  def ipv4(self, arg):
    self.pdu.ipv4 = resource_set.resource_set_ipv4(arg)

  def ipv6(self, arg):
    self.pdu.ipv6 = resource_set.resource_set_ipv6(arg)

dispatch = dict((x.__name__, x) for x in (self, bsc, parent, child, repository, route_origin))

def usage():
  print "Usage:", sys.argv[0]
  for k,v in dispatch.iteritems():
    print " ", k, " ".join(["--" + x + "=x" for x in v.attributes]), " ".join(["--" + x for x in v.booleans])
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
  rng.assertValid(elt)
  print lxml.etree.tostring(elt, pretty_print=True, encoding="us-ascii", xml_declaration=True)
