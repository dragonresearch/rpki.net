# $Id$

"""
Command line program to simulate behavior of the IR back-end.
"""

import glob, rpki.left_right, rpki.relaxng, getopt, sys, lxml.etree

class command(object):

  def getopt(self, argv):
    opts, args = getopt.getopt(argv, "", [x + "=" for x in self.attributes] + [x for x in self.booleans])
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

class self(command, rpki.left_right.self_elt):

  def handle_extension(self, arg):
    kv = arg.split(":", 1)
    self.extensions[k] = v

class bsc(command, rpki.left_right.bsc_elt):

  def handle_signing_cert(self, arg):
    self.signing_cert.append(read_cert(arg))

class parent(command, rpki.left_right.parent_elt):
  pass

class child(command, rpki.left_right.child_elt):
  pass

class repository(command, rpki.left_right.repository_elt):
  pass

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
    print " ", k, " ".join(["--" + x + "=" for x in v.attributes]), " ".join(["--" + x for x in v.booleans])
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
