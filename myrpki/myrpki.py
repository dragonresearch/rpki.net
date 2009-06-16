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

import subprocess, csv, re, os, ConfigParser

from xml.etree.ElementTree import Element, SubElement, ElementTree

cfg_file        = "myrpki.conf"
myrpki_section  = "myrpki"
namespace       = "http://www.hactrn.net/uris/rpki/myrpki/"

cfg = ConfigParser.RawConfigParser()
cfg.read(cfg_file)

my_handle         = cfg.get(myrpki_section, "handle")
roa_csv_file      = cfg.get(myrpki_section, "roa_csv")
validity_csv_file = cfg.get(myrpki_section, "validity_csv")
prefix_csv_file   = cfg.get(myrpki_section, "prefix_csv")
asn_csv_file      = cfg.get(myrpki_section, "asn_csv")
bpki_ca_cert_file = cfg.get(myrpki_section, "bpki_ca_certificate")
bpki_ca_key_file  = cfg.get(myrpki_section, "bpki_ca_key")
bpki_ee_cert_file = cfg.get(myrpki_section, "bpki_ee_certificate")
bpki_ee_req_file  = cfg.get(myrpki_section, "bpki_ee_pkcs10")
output_filename   = cfg.get(myrpki_section, "output-filename")

v4regexp = re.compile("^[-0-9./]+$", re.I)
v6regexp = re.compile("^[-0-9:/]+$", re.I)

class comma_set(set):

  def __str__(self):
    return ",".join(self)

class roa_request(object):

  def __init__(self, asn):
    self.asn = asn
    self.v4 = comma_set()
    self.v6 = comma_set()

  def add(self, prefix):
    if v4regexp.match(prefix):
      self.v4.add(prefix)
    elif v6regexp.match(prefix):
      self.v6.add(prefix)
    else:
      raise RuntimeError, 'Bad prefix syntax: "%s"' % prefix

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

class child(object):

  def __init__(self, handle):
    self.handle = handle
    self.asns = comma_set()
    self.v4 = comma_set()
    self.v6 = comma_set()
    self.validity = None

  def add(self, prefix = None, asn = None, validity = None):
    if prefix is not None:
      if v4regexp.match(prefix):
        self.v4.add(prefix)
      elif v6regexp.match(prefix):
        self.v6.add(prefix)
      else:
        raise RuntimeError, 'Bad prefix syntax: "%s"' % prefix
    if asn is not None:
      self.asns.add(asn)
    if validity is not None:
      self.validity = validity

  def xml(self, e):
    return SubElement(e, "child",
                      handle = self.handle,
                      valid_until = self.validity,
                      asns = str(self.asns),
                      v4 = str(self.v4),
                      v6 = str(self.v6))

class children(dict):

  def add(self, handle, prefix = None, asn = None, validity = None):
    if handle not in self:
      self[handle] = child(handle)
    self[handle].add(prefix = prefix, asn = asn, validity = validity)

  def xml(self, e):
    for c in self.itervalues():
      c.xml(e)

def csv_open(filename, delimiter = "\t", dialect = None):
  return csv.reader(open(filename, "rb"), dialect = dialect, delimiter = delimiter)

def PEMElement(e, tag, filename):
  e = SubElement(e, tag)
  e.text = "".join(p.strip() for p in open(filename).readlines()[1:-1])

def bpki_ca(e):

  if not os.path.exists(bpki_ca_key_file):
    subprocess.check_call(("openssl", "genrsa",
                           "-out", bpki_ca_key_file,
                           "2048"))

  if not os.path.exists(bpki_ca_cert_file):
    subprocess.check_call(("openssl", "req", "-new", "-sha256", "-x509",
                           "-config", cfg_file,
                           "-extensions", "req_x509_ext",
                           "-key", bpki_ca_key_file,
                           "-out", bpki_ca_cert_file))

  PEMElement(e, "bpki_ca_certificate", bpki_ca_cert_file)

def bpki_ee(e):

  if os.path.exists(bpki_ee_req_file):

    if not os.path.exists(bpki_ee_cert_file):
      subprocess.check_call(("openssl", "x509", "-req", "-sha256", "-days", "360",
                             "-CA", bpki_ca_cert_file,
                             "-CAkey", bpki_ca_key_file,
                             "-in", bpki_ee_req_file,
                             "-out", bpki_ee_cert_file, 
                             "-CAcreateserial"))

    PEMElement(e, "bpki_ee_certificate", bpki_ee_cert_file)

def extract_resources():
  pass

roas = roa_requests()
kids = children()

# format:  p/n-m asn
for pnm, asn in csv_open(roa_csv_file):
  roas.add(asn = asn, prefix = pnm)

# childname date
for handle, date in csv_open(validity_csv_file):
  kids.add(handle = handle, validity = date)

# childname p/n
for handle, pn in csv_open(prefix_csv_file):
  kids.add(handle = handle, prefix = pn)

# childname asn
for handle, asn in csv_open(asn_csv_file):
  kids.add(handle = handle, asn = asn)

e = Element("myrpki", xmlns = namespace, version = "1", handle = my_handle)
roas.xml(e)
kids.xml(e)
bpki_ca(e)
bpki_ee(e)

ElementTree(e).write(output_filename + ".tmp")
os.rename(output_filename + ".tmp", output_filename)
