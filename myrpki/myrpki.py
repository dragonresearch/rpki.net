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

import subprocess, csv, re, os, getopt, sys, ConfigParser

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
  def from_csv(cls, children_csv_file, prefix_csv_file, asn_csv_file, cfg_file, bpki_dir):
    self = cls()
    # childname date pemfile
    for handle, date, pemfile in csv_open(children_csv_file):
      self.add(handle = handle, validity = date, ta = xcert(pemfile, bpki_dir, cfg_file))
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
  def from_csv(cls, parents_csv_file, cfg_file, bpki_dir):
    self = cls()
    # parentname uri pemfile
    for handle, uri, pemfile in csv_open(parents_csv_file):
      self.add(handle = handle, uri = uri, ta = xcert(pemfile, bpki_dir, cfg_file))
    return self

def csv_open(filename, delimiter = "\t", dialect = None):
  return csv.reader(open(filename, "rb"), dialect = dialect, delimiter = delimiter)

def xcert(pemfile, bpki_dir, cfg_file):

  if not pemfile:
    return None
  if not os.path.exists(pemfile):
    raise RuntimeError, "PEM file %r does not exist" % (pemfile,)

  # Extract public key and subject name from PEM file and hash it so
  # we can use the result as a tag for cross-certifying this cert.

  p1 = subprocess.Popen(("openssl", "x509", "-noout", "-pubkey", "-subject", "-in", pemfile), stdout = subprocess.PIPE)
  p2 = subprocess.Popen(("openssl", "dgst", "-md5"), stdin = p1.stdout, stdout = subprocess.PIPE)
  xcertfile = "%s/%s.xcert.pem" % (bpki_dir, p2.communicate()[0].strip())
  if p1.wait() != 0 or p2.wait() != 0:
    raise RuntimeError, "Couldn't generate cross-certification tag for %r" % pemfile

  # Cross-certify the pemfile we were given, if we haven't already.
  # This only works for self-signed certs, due to limitations of the
  # OpenSSL command line tool.

  if not os.path.exists(xcertfile):
    subprocess.check_call(("openssl", "ca", "-verbose", "-notext", "-batch",
                           "-config", cfg_file,
                           "-ss_cert", pemfile,
                           "-out", xcertfile,
                           "-extensions", "ca_ca_x509_ext"))

  # This should probably change to be the file content, coordinate with PEMElement()
  return xcertfile

def PEMElement(e, tag, filename):
  e = SubElement(e, tag)
  e.text = "".join(p.strip() for p in open(filename).readlines()[1:-1])

def bpki_setup(bpki_ca_key_file, bpki_ca_cert_file, bpki_crl_file, bpki_index_file, cfg_file,
               bpki_dir, bpki_serial_file, bpki_crl_number_file, bpki_ee_req_file, bpki_ee_cert_file):

  # Create our BPKI database directory
  if not os.path.exists(bpki_dir):
    os.makedirs(bpki_dir)

  # Create our trust anchor key
  if not os.path.exists(bpki_ca_key_file):
    subprocess.check_call(("openssl", "genrsa",
                           "-out", bpki_ca_key_file,
                           "2048"))

  # Create our self-signed trust anchor
  if not os.path.exists(bpki_ca_cert_file):
    subprocess.check_call(("openssl", "req", "-new", "-sha256", "-x509", "-verbose",
                           "-config", cfg_file,
                           "-extensions", "req_x509_ext",
                           "-key", bpki_ca_key_file,
                           "-out", bpki_ca_cert_file))

  # Create empty index file for "openssl ca"
  if not os.path.exists(bpki_index_file):
    f = open(bpki_index_file, "w")
    f.close()

  # Create serial number file for "openssl ca"
  if not os.path.exists(bpki_serial_file):
    f = open(bpki_serial_file, "w")
    f.write("01\n")
    f.close()

  # Create CRL number file for "openssl ca"
  if not os.path.exists(bpki_crl_number_file):
    f = open(bpki_crl_number_file, "w")
    f.write("01\n")
    f.close()

  # Create CRL
  if not os.path.exists(bpki_crl_file):
    subprocess.check_call(("openssl", "ca", "-batch", "-verbose", "-batch", "-notext",
                           "-gencrl",
                           "-config", cfg_file,
                           "-out", bpki_crl_file,
                           "-config", cfg_file))

  # Create BSC EE cert
  if os.path.exists(bpki_ee_req_file) and not os.path.exists(bpki_ee_cert_file):
    subprocess.check_call(("openssl", "ca", "-verbose", "-batch", "-notext",
                           "-config", cfg_file,
                           "-extensions", "ca_ee_x509_ext",
                           "-in", bpki_ee_req_file,
                           "-out", bpki_ee_cert_file))

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
  bpki_dir             = cfg.get(myrpki_section, "bpki_ca_dir")
  bpki_ca_cert_file    = cfg.get(myrpki_section, "bpki_ca_certificate")
  bpki_ca_key_file     = cfg.get(myrpki_section, "bpki_ca_key")
  bpki_ee_cert_file    = cfg.get(myrpki_section, "bpki_ee_certificate")
  bpki_ee_req_file     = cfg.get(myrpki_section, "bpki_ee_pkcs10")
  bpki_crl_file        = cfg.get(myrpki_section, "bpki_crl")
  bpki_index_file      = cfg.get(myrpki_section, "bpki_index")
  bpki_serial_file     = cfg.get(myrpki_section, "bpki_serial")
  bpki_crl_number_file = cfg.get(myrpki_section, "bpki_crl_number")
  output_filename      = cfg.get(myrpki_section, "output_filename")
  relaxng_schema       = cfg.get(myrpki_section, "relaxng_schema")

  bpki_setup(
    bpki_ca_cert_file    = bpki_ca_cert_file,
    bpki_ca_key_file     = bpki_ca_key_file,
    bpki_crl_file        = bpki_crl_file,
    bpki_dir             = bpki_dir,
    bpki_ee_cert_file    = bpki_ee_cert_file,
    bpki_ee_req_file     = bpki_ee_req_file,
    bpki_index_file      = bpki_index_file,
    bpki_serial_file     = bpki_serial_file,
    bpki_crl_number_file = bpki_crl_number_file,
    cfg_file             = cfg_file)

  e = Element("myrpki", xmlns = namespace, version = "1", handle = my_handle)

  roa_requests.from_csv(roa_csv_file).xml(e)

  children.from_csv(
    children_csv_file = children_csv_file,
    prefix_csv_file = prefix_csv_file,
    asn_csv_file = asn_csv_file,
    cfg_file = cfg_file,
    bpki_dir = bpki_dir).xml(e)

  parents.from_csv(
    parents_csv_file = parents_csv_file,
    cfg_file = cfg_file,
    bpki_dir = bpki_dir).xml(e)

  PEMElement(e, "bpki_ca_certificate", bpki_ca_cert_file)
  PEMElement(e, "bpki_crl", bpki_crl_file)

  if os.path.exists(bpki_ee_cert_file):
    PEMElement(e, "bpki_ee_certificate", bpki_ee_cert_file)

  ElementTree(e).write(output_filename + ".tmp")
  os.rename(output_filename + ".tmp", output_filename)

if __name__ == "__main__":
  main()
