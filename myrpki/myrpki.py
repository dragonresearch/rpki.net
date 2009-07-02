"""
Basic plan here is to read in csv files for tabular data (ROA
requests, child ASN assignments, child prefix assignments), read
command line or magic file for my own handle, and read or generate PEM
for BPKI CA certificate and BPKI EE certificate (cannot do latter
without corresponding BPKI EE PKCS #10).  Whack all this together and
generate some XML thing (format still in flux, see schema).

$Id$

Copyright (C) 2009  Internet Systems Consortium ("ISC")

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
"""

import subprocess, csv, re, os, getopt, sys, ConfigParser, base64

from xml.etree.ElementTree import Element, SubElement, ElementTree

namespace = "http://www.hactrn.net/uris/rpki/myrpki/"

class comma_set(set):

  def __str__(self):
    return ",".join(self)

class roa_request(object):

  v4re = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+(-[0-9]+)?$", re.I)
  v6re = re.compile("^([0-9a-f]{0,4}:){0,15}[0-9a-f]{0,4}/[0-9]+(-[0-9]+)?$", re.I)

  def __init__(self, asn):
    self.asn = asn
    self.v4 = comma_set()
    self.v6 = comma_set()

  def __repr__(self):
    return "<%s asn %s v4 %s v6 %s>" % (self.__class__.__name__, self.asn, self.v4, self.v6)

  def add(self, prefix):
    if self.v4re.match(prefix):
      self.v4.add(prefix)
    elif self.v6re.match(prefix):
      self.v6.add(prefix)
    else:
      raise RuntimeError, "Bad prefix syntax: %r" % (prefix,)

  def xml(self, e):
    return SubElement(e, "roa_request",
                      asn = self.asn,
                      v4 = str(self.v4),
                      v6 = str(self.v6))

class roa_requests(dict):

  def add(self, asn, prefix):
    if asn not in self:
      self[asn] = roa_request(asn)
    self[asn].add(prefix)

  def xml(self, e):
    for r in self.itervalues():
      r.xml(e)

  @classmethod
  def from_csv(cls, roa_csv_file):
    self = cls()
    # format:  p/n-m asn
    for pnm, asn in csv_open(roa_csv_file):
      self.add(asn = asn, prefix = pnm)
    return self

class child(object):

  v4re = re.compile("^(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+)|(([0-9]{1,3}\.){3}[0-9]{1,3}-([0-9]{1,3}\.){3}[0-9]{1,3})$", re.I)
  v6re = re.compile("^(([0-9a-f]{0,4}:){0,15}[0-9a-f]{0,4}/[0-9]+)|(([0-9a-f]{0,4}:){0,15}[0-9a-f]{0,4}-([0-9a-f]{0,4}:){0,15}[0-9a-f]{0,4})$", re.I)

  def __init__(self, handle):
    self.handle = handle
    self.asns = comma_set()
    self.v4 = comma_set()
    self.v6 = comma_set()
    self.validity = None
    self.ta = None

  def __repr__(self):
    return "<%s v4 %s v6 %s asns %s validity %s ta %s>" % (self.__class__.__name__, self.v4, self.v6, self.asns, self.validity, self.ta)

  def add(self, prefix = None, asn = None, validity = None, ta = None):
    if prefix is not None:
      if self.v4re.match(prefix):
        self.v4.add(prefix)
      elif self.v6re.match(prefix):
        self.v6.add(prefix)
      else:
        raise RuntimeError, "Bad prefix syntax: %r" % (prefix,)
    if asn is not None:
      self.asns.add(asn)
    if validity is not None:
      self.validity = validity
    if ta is not None:
      self.ta = ta

  def xml(self, e):
    e2 = SubElement(e, "child",
                    handle = self.handle,
                    valid_until = self.validity,
                    asns = str(self.asns),
                    v4 = str(self.v4),
                    v6 = str(self.v6))
    if self.ta:
      PEMElement(e2, "bpki_ta", self.ta)
    return e2

class children(dict):

  def add(self, handle, prefix = None, asn = None, validity = None, ta = None):
    if handle not in self:
      self[handle] = child(handle)
    self[handle].add(prefix = prefix, asn = asn, validity = validity, ta = ta)

  def xml(self, e):
    for c in self.itervalues():
      c.xml(e)

  @classmethod
  def from_csv(cls, children_csv_file, prefix_csv_file, asn_csv_file, xcert):
    self = cls()
    # childname date pemfile
    for handle, date, pemfile in csv_open(children_csv_file):
      self.add(handle = handle, validity = date, ta = xcert(pemfile))
    # childname p/n
    for handle, pn in csv_open(prefix_csv_file):
      self.add(handle = handle, prefix = pn)
    # childname asn
    for handle, asn in csv_open(asn_csv_file):
      self.add(handle = handle, asn = asn)
    return self

class parent(object):

  def __init__(self, handle):
    self.handle = handle
    self.uri = None
    self.ta = None

  def __repr__(self):
    return "<%s uri %s ta %s>" % (self.__class__.__name__, self.uri, self.ta)

  def add(self, uri = None, ta = None):
    if uri is not None:
      self.uri = uri
    if ta is not None:
      self.ta = ta

  def xml(self, e):
    e2 = SubElement(e, "parent",
                    handle = self.handle,
                    uri = self.uri)
    if self.ta:
      PEMElement(e2, "bpki_ta", self.ta)
    return e2

class parents(dict):

  def add(self, handle, uri = None, ta = None):
    if handle not in self:
      self[handle] = parent(handle)
    self[handle].add(uri = uri, ta = ta)

  def xml(self, e):
    for c in self.itervalues():
      c.xml(e)

  @classmethod
  def from_csv(cls, parents_csv_file, xcert):
    self = cls()
    # parentname uri pemfile
    for handle, uri, pemfile in csv_open(parents_csv_file):
      self.add(handle = handle, uri = uri, ta = xcert(pemfile))
    return self

def csv_open(filename, delimiter = "\t", dialect = None):
  return csv.reader(open(filename, "rb"), dialect = dialect, delimiter = delimiter)

def PEMElement(e, tag, filename):
  e = SubElement(e, tag)
  e.text = "".join(p.strip() for p in open(filename).readlines()[1:-1])

class CA(object):

  debug = False

  def __init__(self, cfg, dir, cer):
    self.cfg    = cfg
    self.dir    = dir
    self.cer    = cer
    self.key    = dir + "/ca.key"
    self.req    = dir + "/ca.req"
    self.crl    = dir + "/ca.crl"
    self.index  = dir + "/index"
    self.serial = dir + "/serial"
    self.crlnum = dir + "/crl_number"

  def run_ca(self, *args, **env):
    cmd = ("openssl", "ca", "-notext", "-batch", "-config",  self.cfg) + args
    env = env.copy()
    if "PATH" in os.environ:
      env["PATH"] = os.environ["PATH"]
    if self.debug:
      print "cmd: %r" % (cmd,)
      print "env: %r" % (env,)
    subprocess.check_call(cmd, env = env)

  def setup(self):

    if not os.path.exists(self.dir):
      os.makedirs(self.dir)

    if not os.path.exists(self.index):
      f = open(self.index, "w")
      f.close()

    if not os.path.exists(self.serial):
      f = open(self.serial, "w")
      f.write("01\n")
      f.close()

    if not os.path.exists(self.crlnum):
      f = open(self.crlnum, "w")
      f.write("01\n")
      f.close()

    if not os.path.exists(self.key) or not os.path.exists(self.req):
      subprocess.check_call(("openssl", "req", "-new",
                             #"-verbose",
                             "-sha256", "-newkey", "rsa:2048",
                             "-config", self.cfg,
                             "-extensions", "req_x509_ext",
                             "-keyout", self.key,
                             "-out",    self.req))

    if not os.path.exists(self.cer):
      self.run_ca("-selfsign", "-extensions", "ca_x509_ext_ca", "-in", self.req, "-out", self.cer)

    if not os.path.exists(self.crl):
      subprocess.check_call(("openssl", "ca", "-batch", "-batch", "-notext",
                             #"-verbose",
                             "-config",     self.cfg,
                             "-gencrl",
                             "-out",        self.crl))

  def bsc(self, e, pkcs10):

    if pkcs10 is None:
      return

    p = subprocess.Popen(("openssl", "dgst", "-md5"), stdin = subprocess.PIPE, stdout = subprocess.PIPE)
    hash = p.communicate(pkcs10)[0].strip()
    if p.wait() != 0:
      raise RuntimeError, "Couldn't hash PKCS#10 request"

    req_file = "%s/bsc.%s.req" % (self.dir, hash)
    cer_file = "%s/bsc.%s.cer" % (self.dir, hash)

    if not os.path.exists(cer_file):

      p = subprocess.Popen(("openssl", "req", "-inform", "DER", "-out", req_file), stdin = subprocess.PIPE)
      p.communicate(pkcs10)
      if p.wait() != 0:
        raise RuntimeError, "Couldn't save PKCS #10 in PEM format"

      subprocess.check_call(("openssl", "ca", "-batch", "-notext",
                             #"-verbose",
                             "-extensions", "ca_x509_ext_bsc",
                             "-config", self.cfg,
                             "-in",     req_file,
                             "-out",    cer_file))

    PEMElement(e, "bpki_bsc_certificate", cer_file)
    PEMElement(e, "bpki_bsc_pkcs10",      req_file)

  def xcert(self, cert):

    if not cert:
      return None

    if not os.path.exists(cert):
      raise RuntimeError, "PEM file %r does not exist" % (cert,)

    # Extract public key and subject name from PEM file and hash it so
    # we can use the result as a tag for cross-certifying this cert.

    p1 = subprocess.Popen(("openssl", "x509", "-noout", "-pubkey", "-subject", "-in", cert), stdout = subprocess.PIPE)
    p2 = subprocess.Popen(("openssl", "dgst", "-md5"), stdin = p1.stdout, stdout = subprocess.PIPE)

    xcert = "%s/xcert.%s.cer" % (self.dir, p2.communicate()[0].strip())

    if p1.wait() != 0 or p2.wait() != 0:
      raise RuntimeError, "Couldn't generate cross-certification tag for %r" % cert

    # Cross-certify the cert we were given, if we haven't already.
    # This only works for self-signed certs, due to limitations of the
    # OpenSSL command line tool.

    if not os.path.exists(xcert):
      subprocess.check_call(("openssl", "ca", "-notext", "-batch",
                             #"-verbose", 
                             "-config",  self.cfg,
                             "-ss_cert", cert,
                             "-out",     xcert,
                             "-extensions", "ca_x509_ext_xcert"))

    return xcert

def extract_resources():
  pass

def main():

  cfg_file        = "myrpki.conf"
  myrpki_section  = "myrpki"

  opts, argv = getopt.getopt(sys.argv[1:], "c:h:?", ["config=", "help"])
  for o, a in opts:
    if o in ("-h", "--help", "-?"):
      print __doc__
      sys.exit(0)
    elif o in ("-c", "--config"):
      cfg_file = a
  if argv:
    raise RuntimeError, "Unexpected arguments %r" % (argv,)

  cfg = ConfigParser.RawConfigParser()
  cfg.read(cfg_file)

  my_handle            = cfg.get(myrpki_section, "handle")
  roa_csv_file         = cfg.get(myrpki_section, "roa_csv")
  children_csv_file    = cfg.get(myrpki_section, "children_csv")
  parents_csv_file     = cfg.get(myrpki_section, "parents_csv")
  prefix_csv_file      = cfg.get(myrpki_section, "prefix_csv")
  asn_csv_file         = cfg.get(myrpki_section, "asn_csv")
  bpki_dir             = cfg.get(myrpki_section, "bpki_ca_directory")
  bpki_cacert          = cfg.get(myrpki_section, "bpki_ca_certificate")
  xml_filename         = cfg.get(myrpki_section, "xml_filename")

  bsc_req = None
  if os.path.exists(xml_filename):
    e = ElementTree(file = xml_filename).getroot()
    r = e.findtext("{%s}%s" % (namespace, "bpki_bsc_pkcs10"))
    if r:
      bsc_req = base64.b64decode(r)

  bpki = CA(cfg_file, bpki_dir, bpki_cacert)
  bpki.setup()

  e = Element("myrpki", xmlns = namespace, version = "1", handle = my_handle)

  roa_requests.from_csv(roa_csv_file).xml(e)

  children.from_csv(
    children_csv_file = children_csv_file,
    prefix_csv_file = prefix_csv_file,
    asn_csv_file = asn_csv_file,
    xcert = bpki.xcert).xml(e)

  parents.from_csv(
    parents_csv_file = parents_csv_file,
    xcert = bpki.xcert).xml(e)

  PEMElement(e, "bpki_ca_certificate", bpki.cer)
  PEMElement(e, "bpki_crl",            bpki.crl)

  bpki.bsc(e, bsc_req)

  ElementTree(e).write(xml_filename + ".tmp")
  os.rename(xml_filename + ".tmp", xml_filename)

if __name__ == "__main__":
  main()
