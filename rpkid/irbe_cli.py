"""
Command line IR back-end control program for rpkid and pubd.

$Id$

Copyright (C) 2009--2010  Internet Systems Consortium ("ISC")

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

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import getopt, sys, textwrap
import rpki.left_right, rpki.http, rpki.x509, rpki.config, rpki.log
import rpki.publication, rpki.async

pem_out = None

class UsageWrapper(textwrap.TextWrapper):
  """
  Call interface around Python textwrap.Textwrapper class.
  """

  def __call__(self, *args):
    """
    Format arguments, with TextWrapper indentation.
    """
    return self.fill(textwrap.dedent(" ".join(args)))

usage_fill = UsageWrapper(subsequent_indent = " " * 4)

class reply_elt_mixin(object):
  """
  Protocol mix-in for printout of reply PDUs.
  """

  is_cmd = False

  def client_reply_decode(self):
    pass

  def client_reply_show(self):
    print self.element_name
    for i in self.attributes + self.elements:
      if getattr(self, i) is not None:
        print "  %s: %s" % (i, getattr(self, i))

class cmd_elt_mixin(reply_elt_mixin):
  """
  Protocol mix-in for command line client element PDUs.
  """

  is_cmd = True

  ## @var excludes
  # XML attributes and elements that should not be allowed as command
  # line arguments.
  excludes = ()

  @classmethod
  def usage(cls):
    """
    Generate usage message for this PDU.
    """
    args = " ".join("--" + x + "=" for x in cls.attributes + cls.elements if x not in cls.excludes)
    bools = " ".join("--" + x for x in cls.booleans)
    if args and bools:
      return args + " " + bools
    else:
      return args or bools

  def client_getopt(self, argv):
    """
    Parse options for this class.
    """
    opts, argv = getopt.getopt(argv, "", [x + "=" for x in self.attributes + self.elements if x not in self.excludes] + list(self.booleans))
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

  def client_query_bpki_cert(self, arg):
    """
    Special handler for --bpki_cert option.
    """
    self.bpki_cert = rpki.x509.X509(Auto_file = arg)

  def client_query_glue(self, arg):
    """
    Special handler for --bpki_glue option.
    """
    self.bpki_glue = rpki.x509.X509(Auto_file = arg)

  def client_query_bpki_cms_cert(self, arg):
    """
    Special handler for --bpki_cms_cert option.
    """
    self.bpki_cms_cert = rpki.x509.X509(Auto_file = arg)

  def client_query_cms_glue(self, arg):
    """
    Special handler for --bpki_cms_glue option.
    """
    self.bpki_cms_glue = rpki.x509.X509(Auto_file = arg)

class cmd_msg_mixin(object):
  """
  Protocol mix-in for command line client message PDUs.
  """

  @classmethod
  def usage(cls):
    """
    Generate usage message for this PDU.
    """
    for k, v in cls.pdus.items():
      if v.is_cmd:
        print usage_fill(k, v.usage())

# left-right protcol

class self_elt(cmd_elt_mixin, rpki.left_right.self_elt):
  pass

class bsc_elt(cmd_elt_mixin, rpki.left_right.bsc_elt):

  excludes = ("pkcs10_request",)

  def client_query_signing_cert(self, arg):
    """--signing_cert option."""
    self.signing_cert = rpki.x509.X509(Auto_file = arg)

  def client_query_signing_cert_crl(self, arg):
    """--signing_cert_crl option."""
    self.signing_cert_crl = rpki.x509.CRL(Auto_file = arg)

  def client_reply_decode(self):
    global pem_out
    if pem_out is not None and self.pkcs10_request is not None:
      if isinstance(pem_out, str):
        pem_out = open(pem_out, "w")
      pem_out.write(self.pkcs10_request.get_PEM())

class parent_elt(cmd_elt_mixin, rpki.left_right.parent_elt):
  pass

class child_elt(cmd_elt_mixin, rpki.left_right.child_elt):
  pass

class repository_elt(cmd_elt_mixin, rpki.left_right.repository_elt):
  pass

class list_published_objects_elt(cmd_elt_mixin, rpki.left_right.list_published_objects_elt):
  excludes = ("uri",)

class list_received_resources_elt(cmd_elt_mixin, rpki.left_right.list_received_resources_elt):
  excludes = ("parent_handle", "notBefore", "notAfter", "uri", "sia_uri", "aia_uri", "asn", "ipv4", "ipv6")

class report_error_elt(reply_elt_mixin, rpki.left_right.report_error_elt):
  pass

class left_right_msg(cmd_msg_mixin, rpki.left_right.msg):
  pdus = dict((x.element_name, x)
              for x in (self_elt, bsc_elt, parent_elt, child_elt, repository_elt,
                        list_published_objects_elt, list_received_resources_elt, report_error_elt))

class left_right_sax_handler(rpki.left_right.sax_handler):
  pdu = left_right_msg

class left_right_cms_msg(rpki.left_right.cms_msg):
  saxify = left_right_sax_handler.saxify

# Publication protocol

class config_elt(cmd_elt_mixin, rpki.publication.config_elt):

  def client_query_bpki_crl(self, arg):
    """
    Special handler for --bpki_crl option.
    """
    self.bpki_crl = rpki.x509.CRL(Auto_file = arg)

class client_elt(cmd_elt_mixin, rpki.publication.client_elt):
  pass

class certificate_elt(cmd_elt_mixin, rpki.publication.certificate_elt):
  pass

class crl_elt(cmd_elt_mixin, rpki.publication.crl_elt):
  pass

class manifest_elt(cmd_elt_mixin, rpki.publication.manifest_elt):
  pass

class roa_elt(cmd_elt_mixin, rpki.publication.roa_elt):
  pass

class report_error_elt(reply_elt_mixin, rpki.publication.report_error_elt):
  pass

class publication_msg(cmd_msg_mixin, rpki.publication.msg):
  pdus = dict((x.element_name, x)
              for x in (config_elt, client_elt, certificate_elt, crl_elt, manifest_elt, roa_elt, report_error_elt))

class publication_sax_handler(rpki.publication.sax_handler):
  pdu = publication_msg

class publication_cms_msg(rpki.publication.cms_msg):
  saxify = publication_sax_handler.saxify

# Usage

top_opts = ["config=", "help", "pem_out=", "quiet", "verbose"]

def usage(code = 1):
  print __doc__.strip()
  print
  print "Usage:"
  print
  print "# Top-level options:"
  print usage_fill(*["--" + x for x in top_opts])
  print
  print "# left-right protocol:"
  left_right_msg.usage()
  print
  print "# publication protocol:"
  publication_msg.usage()
  sys.exit(code)

# Main program

rpki.log.init("irbe_cli")

argv = sys.argv[1:]

if not argv:
  usage(0)

cfg_file = "irbe.conf"
verbose = True

opts, argv = getopt.getopt(argv, "c:hpqv?", top_opts)
for o, a in opts:
  if o in ("-?", "-h", "--help"):
    usage(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-p", "--pem_out"):
    pem_out = a
  elif o in ("-q", "--quiet"):
    verbose = False
  elif o in ("-v", "--verbose"):
    verbose = True

if not argv:
  usage(1)

cfg = rpki.config.parser(cfg_file, "irbe_cli")

q_msg_left_right  = []
q_msg_publication = []

while argv:
  if argv[0] in left_right_msg.pdus:
    q_pdu = left_right_msg.pdus[argv[0]]()
    q_msg = q_msg_left_right
  elif argv[0] in publication_msg.pdus:
    q_pdu = publication_msg.pdus[argv[0]]()
    q_msg = q_msg_publication
  else:
    usage(1)
  argv = q_pdu.client_getopt(argv[1:])
  q_msg.append(q_pdu)

if q_msg_left_right:

  class left_right_proto(object):
    cms_msg = left_right_cms_msg
    msg     = left_right_msg

  call_rpkid = rpki.async.sync_wrapper(rpki.http.caller(
    proto       = left_right_proto,
    client_key  = rpki.x509.RSA( Auto_file = cfg.get("rpkid-irbe-key")),
    client_cert = rpki.x509.X509(Auto_file = cfg.get("rpkid-irbe-cert")),
    server_ta   = rpki.x509.X509(Auto_file = cfg.get("rpkid-bpki-ta")),
    server_cert = rpki.x509.X509(Auto_file = cfg.get("rpkid-cert")),
    url         = cfg.get("rpkid-url"),
    debug       = verbose))

  call_rpkid(*q_msg_left_right)

if q_msg_publication:

  class publication_proto(object):
    msg     = publication_msg
    cms_msg = publication_cms_msg

  call_pubd = rpki.async.sync_wrapper(rpki.http.caller(
    proto       = publication_proto,
    client_key  = rpki.x509.RSA( Auto_file = cfg.get("pubd-irbe-key")),
    client_cert = rpki.x509.X509(Auto_file = cfg.get("pubd-irbe-cert")),
    server_ta   = rpki.x509.X509(Auto_file = cfg.get("pubd-bpki-ta")),
    server_cert = rpki.x509.X509(Auto_file = cfg.get("pubd-cert")),
    url         = cfg.get("pubd-url")),
    debug       = verbose)

  call_pubd(*q_msg_publication)
