# $Id$

"""
Command line IR back-end control program.

The query back-channel is handled by a separate program.
"""

import sys, lxml.etree, lxml.sax
import rpki.left_right, rpki.relaxng, rpki.cms, rpki.https, rpki.x509, rpki.config

dispatch = dict((x.element_name, x)
                for x in (rpki.left_right.self_elt,
                          rpki.left_right.bsc_elt,
                          rpki.left_right.parent_elt,
                          rpki.left_right.child_elt,
                          rpki.left_right.repository_elt,
                          rpki.left_right.route_origin_elt))

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
    argv = q_pdu.client_getopt(argv[1:])
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
  if True:
    for r_pdu in r_msg:
      r_pdu.client_reply_show()

if __name__ == "__main__": main()
