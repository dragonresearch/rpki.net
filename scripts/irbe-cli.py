# $Id$

"""
Command line program to simulate behavior of the IR back-end.
"""

import glob, rpki.left_right, rpki.relaxng, getopt, sys, lxml.etree

class command(object):

  booleans = ()

  def getopt(self, argv):
    if self.options:
      opts, args = getopt.getopt(argv, "", [x[2:] + "=" for x in self.options] + [x[2:] for x in self.booleans])
      for o, a in opts:
        handler = getattr(self, o[2:], None)
        if handler is not None:
          handler(a)
        elif o in self.booleans:
          setattr(self.pdu, o, True)
        else:
          assert o in self.options
          setattr(self.pdu, o, a)
      return args
    else:
      return argv

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

  options = ("--action", "--self_id", "--extension")
  booleans = ("--rekey", "--reissue", "--revoke", "--run_now", "--publish_world_now")

  def __init__(self):
    self.pdu = rpki.left_right.self_elt()

  def extension(self, arg):
    kv = arg.split(":", 1)
    self.pdu.extensions[k] = v

class bsc(command):

  options = ("--action", "--self_id", "--bsc_id", "--key_type", "--hash_alg", "--key_length", "--signing_cert")
  booleans = ("--generate_keypair",)

  def __init__(self):
    self.pdu = rpki.left_right.bsc_elt()

  def signing_cert(self, arg):
    self.pdu.signing_cert.append(read_cert(arg))

class parent(command):

  options = ("--action", "--self_id", "--parent_id", "--peer_ta", "--bsc_link", "--repository_link", "--sia_base", "--peer_contact")
  booleans = ("--rekey", "--revoke", "--reissue")

  def __init__(self):
    self.pdu = rpki.left_right.parent_elt()

class child(command):

  options = ("--action", "--self_id", "--child_id", "--peer_ta", "--bsc_link", "--child_db_id")
  booleans = ("--reissue",)

  def __init__(self):
    self.pdu = rpki.left_right.child_elt()

class repository(command):

  options = ("--action", "--self_id", "--repository", "--peer_ta", "--bsc_link", "--peer_contact")

  def __init__(self):
    self.pdu = rpki.left_right.repository_elt()

class route_origin(command):

  options = ("--action", "--self_id", "--route_origin_id", "--asn", "--ipv4", "--ipv6")
  booleans = ("--suppress_publication",)

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
    print " ", " ".join((k,) + v.options + v.booleans)
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
