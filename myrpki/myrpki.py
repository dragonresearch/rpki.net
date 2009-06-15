# $Id$

# Basic plan here is to read in csv files for tabular data (roa
# requests, child asn assignments, child prefix assignments), read
# command line or magic file for my own handle, and read or generate
# pem for bpki ca cert and bpki ee cert (cannot do latter without
# corresponding bpki ee pkcs10).  whack all this together and generate
# some xml thing in format to be determined (need to write schema).

import subprocess, csv, sys, os

from xml.etree.ElementTree import Element, SubElement, ElementTree, tostring

# The following should all be configurable on command line, as perhaps
# should the csv conventions (dialect, delimiter, see csv module doc
# for all the fun one can have here).  For now, just wire all this in,
# add command line junk later.

my_handle         = "wombat"
roa_csv_file      = "roas.csv"
validity_csv_file = "validity.csv"
prefixes_csv_file = "prefixes.csv"
asns_csv_file     = "asns.csv"
bpki_ca_conf_file = "bpki-ca-cert.conf"
bpki_ca_cert_file = "bpki-ca-cert.pem"
bpki_ca_req_file  = "bpki-ca-pkcs10.pem"
bpki_ca_key_file  = "bpki-ca-key.pem"
bpki_ee_cert_file = "bpki-ee-cert.pem"
bpki_ee_req_file  = "bpki-ee-pkcs10.pem"

class comma_set(set):

  def __str__(self):
    return ",".join(self)

class roa_request(object):

  def __init__(self, asn):
    self.asn = asn
    self.prefixes = comma_set()

  def add(self, prefix):
    self.prefixes.add(prefix)

  def xml(self):
    return Element("roa_request", asn = self.asn, prefixes = str(self.prefixes))

class roa_requests(dict):

  def add(self, asn, prefix):
    if asn not in self:
      self[asn] = roa_request(asn)
    self[asn].add(prefix)

  def xml(self):
    e = Element("roa_requests")
    for r in self.itervalues():
      e.append(r.xml())
    return e

class child(object):

  def __init__(self, handle):
    self.handle = handle
    self.asns = comma_set()
    self.prefixes = comma_set()
    self.validity = None

  def add(self, prefix = None, asn = None, validity = None):
    if prefix is not None:
      self.prefixes.add(prefix)
    if asn is not None:
      self.asns.add(asn)
    if validity is not None:
      self.validity = validity

  def xml(self):
    return Element("child", handle = self.handle, valid_until = self.validity,
                   asns = str(self.asns), prefixes = str(self.prefixes))

class children(dict):

  def add(self, handle, prefix = None, asn = None, validity = None):
    if handle not in self:
      self[handle] = child(handle)
    self[handle].add(prefix = prefix, asn = asn, validity = validity)

  def xml(self):
    e = Element("children")
    for c in self.itervalues():
      e.append(c.xml())
    return e

def csv_open(filename, delimiter = "\t", dialect = None):
  return csv.reader(open(filename, "rb"), dialect = dialect, delimiter = delimiter)

def bpki_ca():

  if not os.path.exists(bpki_ca_key_file):
    subprocess.check_call(("openssl", "genrsa",
                           "-out", bpki_ca_key_file,
                           "2048"))

  if not os.path.exists(bpki_ca_conf_file):
    open(bpki_ca_conf_file, "w").write(bpki_ca_conf_fmt % { "handle" : my_handle })

  if not os.path.exists(bpki_ca_req_file):
    subprocess.check_call(("openssl", "req", "-new", "-sha256",
                           "-config", bpki_ca_conf_file,
                           "-key", bpki_ca_key_file,
                           "-out", bpki_ca_req_file))

  if not os.path.exists(bpki_ca_cert_file):
    subprocess.check_call(("openssl", "x509",  "-req",
                           "-sha256", "-days", "360",
                           "-in", bpki_ca_req_file,
                           "-signkey", bpki_ca_key_file,
                           "-out", bpki_ca_cert_file))

  e = Element("bpki_ca_certificate")
  e.text = "".join(p.strip() for p in open(bpki_ca_cert_file).readlines()[1:-1])
  return e

bpki_ca_conf_fmt = '''\
[req]
default_bits            = 2048
default_md		= sha256
distinguished_name	= req_dn
x509_extensions		= req_x509_ext
prompt			= no

[req_dn]
CN                      = %(handle)s

[req_x509_ext]
basicConstraints	= critical,CA:true
subjectKeyIdentifier	= hash
authorityKeyIdentifier	= keyid:always
'''

def issue_bsc():

  ca_name = my_handle + "bpki-ca"
  ee_name = my_handle + "bpki-ee"

  subprocess.check_call(("openssl", "x509", "-req", "-sha256", "-days", "360",
                         "-CA", ca_name + ".cer", "-CAkey", ca_name + ".key",
                         "-in", ee_name + ".req", "-out", ee_name + ".cer", 
                         "-CAcreateserial"))

  yaml_cert_out(ee_name + ".cer", "bpki_ee")

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
for handle, pn in csv_open(prefixes_csv_file):
  kids.add(handle = handle, prefix = pn)

# childname asn
for handle, asn in csv_open(asns_csv_file):
  kids.add(handle = handle, asn = asn)

e = Element("myrpki", handle = my_handle)
e.append(roas.xml())
e.append(kids.xml())
e.append(bpki_ca())

if True:
  ElementTree(e).write(sys.stdout)
else:
  print tostring(e)
