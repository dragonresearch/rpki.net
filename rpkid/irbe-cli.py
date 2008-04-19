# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Command line IR back-end control program.

The query back-channel is handled by a separate program.
"""

import getopt, sys, lxml.etree, lxml.sax
import rpki.left_right, rpki.relaxng, rpki.https, rpki.x509, rpki.config, rpki.log

pem_out = None

class cmd_mixin(object):
  """Left-right protocol mix-in for command line client."""

  def client_getopt(self, argv):
    """Parse options for this class."""
    opts, argv = getopt.getopt(argv, "", [x + "=" for x in self.attributes + self.elements] + list(self.booleans))
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
    return argv

  def client_query_action(self, arg):
    """Special handler for --action option."""
    self.action = arg
    self.type = "query"

  def client_query_peer_biz_cert(self, arg):
    """Special handler for --peer_biz_cert option."""
    self.peer_biz_cert = rpki.x509.X509(Auto_file=arg)

  def client_query_https_ta(self, arg):
    """Special handler for --peer_biz_glue option."""
    self.peer_biz_glue = rpki.x509.X509(Auto_file=arg)

  def client_reply_decode(self):
    pass

  def client_reply_show(self):
    print self.element_name
    for i in self.attributes + self.elements:
      if getattr(self, i) is not None:
        print "  %s: %s" % (i, getattr(self, i))

class self_elt(cmd_mixin, rpki.left_right.self_elt):

  def client_query_extension_preference(self, arg):
    """--extension_preferences option."""
    k,v = arg.split("=", 1)
    pref = rpki.left_right.extension_preference_elt()
    pref.name = k
    pref.value = v
    self.prefs.append(pref)

class bsc_elt(cmd_mixin, rpki.left_right.bsc_elt):

  def client_query_signing_cert(self, arg):
    """--signing_cert option."""
    self.signing_cert.append(rpki.x509.X509(Auto_file=arg))

  def client_reply_decode(self):
    global pem_out
    if pem_out is not None and self.pkcs10_request is not None:
      if isinstance(pem_out, str):
        pem_out = open(pem_out, "w")
      pem_out.write(self.pkcs10_request.get_PEM())

class parent_elt(cmd_mixin, rpki.left_right.parent_elt):
  pass

class child_elt(cmd_mixin, rpki.left_right.child_elt):
  pass

class repository_elt(cmd_mixin, rpki.left_right.repository_elt):
  pass

class route_origin_elt(cmd_mixin, rpki.left_right.route_origin_elt):

  def client_query_as_number(self, arg):
    """Handle autonomous sequence numbers."""
    self.as_number = long(arg)

  def client_query_ipv4(self, arg):
    """Handle IPv4 addresses."""
    self.ipv4 = resource_set.resource_set_ipv4(arg)

  def client_query_ipv6(self, arg):
    """Handle IPv6 addresses."""
    self.ipv6 = resource_set.resource_set_ipv6(arg)

class msg(rpki.left_right.msg):
  pdus = dict((x.element_name, x)
              for x in (self_elt, bsc_elt, parent_elt, child_elt, repository_elt, route_origin_elt))

class sax_handler(rpki.left_right.sax_handler):
  pdu = msg

top_opts = ["config=", "help", "pem_out="]

def usage(code=1):
  print "Usage:", sys.argv[0], " ".join(["--" + x for x in top_opts])
  for k,v in msg.pdus.items():
    print " ", k, \
          " ".join(["--" + x + "=" for x in v.attributes + v.elements]), \
          " ".join(["--" + x for x in v.booleans])
  sys.exit(code)

# Main program

rpki.log.init("irbe-cli")

argv = sys.argv[1:]

if not argv:
  usage(0)

cfg_file = "irbe.conf"

opts, argv = getopt.getopt(argv, "c:h?", top_opts)
for o, a in opts:
  if o in ("-?", "-h", "--help"):
    usage(0)
  if o in ("-c", "--config"):
    cfg_file = a
  if o == "--pem_out":
    pem_out = a

if not argv:
  usage(1)

cfg = rpki.config.parser(cfg_file, "irbe-cli")

cms_key     = rpki.x509.RSA(       Auto_file  = cfg.get(     "cms-key"))
cms_certs   = rpki.x509.X509_chain(Auto_files = cfg.multiget("cms-cert"))
cms_ta      = rpki.x509.X509(      Auto_file  = cfg.get(     "cms-ta"))
https_key   = rpki.x509.RSA(       Auto_file  = cfg.get(     "https-key"))
https_certs = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-cert"))
https_ta    = rpki.x509.X509(      Auto_file  = cfg.get(     "https-ta"))
https_url   = cfg.get(                                       "https-url")

q_msg = rpki.left_right.msg()

while argv:
  try:
    q_pdu = msg.pdus[argv[0]]()
  except KeyError:
    usage(1)
  argv = q_pdu.client_getopt(argv[1:])
  q_msg.append(q_pdu)

q_elt = q_msg.toXML()
q_cms = rpki.x509.left_right_pdu.build(q_elt, cms_key, cms_certs)

der = rpki.https.client(client_key   = https_key,
                        client_certs = https_certs,
                        server_ta    = https_ta,
                        url          = https_url,
                        msg          = q_cms.get_DER())

r_cms = rpki.x509.left_right(DER = der)
r_elt = r_cms.verify(r_cms, cms_ta)

print r_cms.prettyprint_content()

handler = sax_handler()
lxml.sax.saxify(r_elt, handler)
r_msg = handler.result

for r_pdu in r_msg:
  r_pdu.client_reply_decode()
  #r_pdu.client_reply_show()
