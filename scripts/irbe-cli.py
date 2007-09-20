# $Id$

"""Command line program to simulate behavior of the IR back-end.

This only handles the control channel.  The query back-channel will be
a separate program.
"""

import glob, getopt, sys, lxml.etree, lxml.sax
import rpki.left_right, rpki.relaxng, rpki.cms, rpki.https, rpki.x509, rpki.config

class command(object):
  """Command processor mixin class for left-right protocol objects.

  This class and its derived classes probably should be merged into
  the left-right protocol classes, once this stuff is stable.
  """

  elements = ()

  def getopt(self, argv):
    """Parse options for this class."""
    opts, args = getopt.getopt(argv, "", [x + "=" for x in self.attributes + self.elements] + list(self.booleans))
    for o, a in opts:
      o = o[2:]
      handler = getattr(self, "client_query_" + o, None)
      if handler is not None:
        handler(a)
      elif o in self.booleans:
        setattr(self, o, True)
      else:
        assert o in self.attributes
        setattr(self, o, a)
    return args

  def client_query_action(self, arg):
    """Special handler for --action option."""
    self.action = arg
    self.type = "query"

  def client_query_peer_ta(self, arg):
    """Special handler for --peer_ta option."""
    self.peer_ta = rpki.x509.X509(Auto_file=arg)

  def client_reply_decode(self):
    pass

  def client_reply_show(self):
    self.client_reply_decode()
    print self.element_name
    for i in self.attributes + self.elements:
      print "  " + i + ": " + getattr(self, i)

class self(command, rpki.left_right.self_elt):
  '''"self" command.'''

  elements = ("extension_preference",)

  def client_query_extension_preference(self, arg):
    """--extension_preferences option."""
    k,v = arg.split("=", 1)
    pref = rpki.left_right.extension_preference_elt()
    pref.name = k
    pref.value = v
    self.prefs.append(pref)

class bsc(command, rpki.left_right.bsc_elt):
  '''"bsc" command.'''

  elements = ('signing_cert',)

  def client_query_signing_cert(self, arg):
    """--signing_cert option."""
    self.signing_cert.append(rpki.x509.X509(Auto_file=arg))

class parent(command, rpki.left_right.parent_elt):
  '''"parent" command.'''
  elements = ("peer_ta",)

class child(command, rpki.left_right.child_elt):
  '''"child" command.'''
  elements = ("peer_ta",)

class repository(command, rpki.left_right.repository_elt):
  '''"repository" command.'''
  elements = ("peer_ta",)

class route_origin(command, rpki.left_right.route_origin_elt):
  '''"route_origin" command.'''

  def client_query_as_number(self, arg):
    """Handle autonomous sequence numbers."""
    self.as_number = long(arg)

  def client_query_ipv4(self, arg):
    """Handle IPv4 addresses."""
    self.ipv4 = resource_set.resource_set_ipv4(arg)

  def client_query_ipv6(self, arg):
    """Handle IPv6 addresses."""
    self.ipv6 = resource_set.resource_set_ipv6(arg)

dispatch = dict((x.element_name, x) for x in (self, bsc, parent, child, repository, route_origin))

def usage():
  print "Usage:", sys.argv[0]
  for k,v in dispatch.iteritems():
    print " ", k, \
          " ".join(["--" + x + "=" for x in v.attributes + v.elements]), \
          " ".join(["--" + x for x in v.booleans])
  sys.exit(1)

def main():
  """Main program.

  Work in progress.  At the moment it gets as far as transmitting the
  generated request, but doesn't yet do anything with responses.
  """

  cfg = rpki.config.parser("irbe.conf")
  section = "irbe-cli"

  rng = rpki.relaxng.RelaxNG(cfg.get(section, "rng-schema"))

  privateKey = rpki.x509.RSA_Keypair(PEM_file = cfg.get(section, "https-key"))

  certChain = rpki.x509.X509_chain()
  certChain.load_from_PEM(cfg.multiget(section, "https-cert"))

  x509TrustList = rpki.x509.X509_chain()
  x509TrustList.load_from_PEM(cfg.multiget(section, "https-ta"))

  q_msg = rpki.left_right.msg()

  argv = sys.argv[1:]

  if not argv:
    usage()

  while argv:
    try:
      q_pdu = dispatch[argv[0]]()
    except KeyError:
      usage()
    argv = q_pdu.getopt(argv[1:])
    q_msg.append(q_pdu)

  q_elt = q_msg.toXML()
  q_xml = lxml.etree.tostring(q_elt, pretty_print=True, encoding="us-ascii", xml_declaration=True)
  try:
    rng.assertValid(q_elt)
  except lxml.etree.DocumentInvalid:
    print "Generated request document doesn't pass schema check:"
    print q_xml
    sys.exit(1)

  print "Sending:"
  print q_xml

  q_cms = rpki.cms.encode(q_xml, cfg.get(section, "cms-key"), cfg.multiget(section, "cms-cert"))

  r_cms = rpki.https.client(privateKey=privateKey, certChain=certChain, x509TrustList=x509TrustList,
                            msg=q_cms, url="/left-right")

  r_xml = rpki.cms.decode(r_cms, cfg.get(section, "cms-ta"))

  r_elt = lxml.etree.fromstring(r_xml)
  try:
    rng.assertValid(r_elt)
  except lxml.etree.DocumentInvalid:
    print "Received reply document doesn't pass schema check:"
    print r_xml
    sys.exit(1)

  print "Received:"
  print r_xml

  handler = rpki.left_right.sax_handler()
  lxml.sax.saxify(r_elt, handler)
  r_msg = handler.result

  # Can't enable this until our reply handler methods are merged into rpki.left_right.
  if False:
    for r_pdu in r_msg:
      r_pdu.client_reply_show()

if __name__ == "__main__": main()
