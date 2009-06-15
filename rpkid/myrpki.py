# $Id$

# Basic plan here is to read in csv files for tabular data (roa
# requests, child asn assignments, child prefix assignments), read
# command line or magic file for my own handle, and read or generate
# pem for bpki ca cert and bpki ee cert (cannot do latter without
# corresponding bpki ee pkcs10).  whack all this together and generate
# some xml thing in format to be determined (need to write schema).

import subprocess, csv, sys

from xml.etree.ElementTree import Element, SubElement, ElementTree

# The following should all be configurable on command line, as perhaps
# should the csv conventions (dialect, delimiter, see csv module doc
# for all the fun one can have here).  For now, just wire all this in,
# add command line junk later.

my_handle         = "wombat"
roa_csv_file      = "roas.csv"
validity_csv_file = "validity.csv"
prefixes_csv_file = "prefixes.csv"
asns_csv_file     = "asns.csv"

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

def indent(elem, level = 0):
  # http://effbot.org/zone/element-lib.htm#prettyprint
  i = "\n" + level * "  "
  if len(elem):
    if not elem.text or not elem.text.strip():
      elem.text = i + "  "
    if not elem.tail or not elem.tail.strip():
      elem.tail = i
    for elem in elem:
      indent(elem, level + 1)
    if not elem.tail or not elem.tail.strip():
      elem.tail = i
  else:
    if level and (not elem.tail or not elem.tail.strip()):
      elem.tail = i

def csv_open(filename, delimiter = "\t", dialect = None):
  return csv.reader(open(filename, "rb"), dialect = dialect, delimiter = delimiter)

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
indent(e)
ElementTree(e).write(sys.stdout)

# rest of this is yesterday's code that hasn't been converted yet

# modes: --create-bpki, --issue-bsc, --extract-resources

def create_bpki():
  name = my_handle + "bpki-ca"

  subprocess.check_call(("openssl", "genrsa", "-out", name + ".key", "2048"))

  subprocess.check_call(("openssl", "req", "-new", "-sha256",
              "-key", name + ".key", "-out", name + ".req"))

  subprocess.check_call(("openssl", "x509",  "-req",  "-sha256",
                         "-in", name + ".req", "-out", name + ".cer",
                         "-signkey", name + ".key", "-days", "360"))

  yaml_cert_out(name + ".cer", "bpki_ca")

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

