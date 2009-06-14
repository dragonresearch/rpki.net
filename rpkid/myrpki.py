# $Id$

# Basic plan here is to read in csv files for tabular data (roa
# requests, child asn assignments, child prefix assignments), read
# command line or magic file for my own handle, and read or generate
# pem for bpki ca cert and bpki ee cert (cannot do latter without
# corresponding bpki ee pkcs10).  whack all this together and generate
# some xml thing in format to be determined (need to write schema).

import subprocess, csv, xml.etree.ElementTree

# The following should all be configurable on command line, as perhaps
# should the csv conventions (dialect, delimiter, see csv module doc
# for all the fun one can have here).  For now, just wire all this in,
# add command line junk later.

my_handle         = "wombat"
roa_csv_file      = "roas.csv"
validity_csv_file = "validity.csv"
prefixes_csv_file = "prefixes.csv"
asns_csv_file     = "asns.csv"

class roa_request(object):

  def __init__(self, asn):
    self.asn = asn
    self.prefixes = set()

  requests = {}

  @classmethod
  def add(cls, asn, prefix):
    if asn not in cls.requests:
      cls.requests[asn] = cls(asn)
    cls.requests[asn].prefixes.add(prefix)

  def __str__(self):
    return self.asn + " " + ",".join(self.prefixes)

  @classmethod
  def show(cls):
    for r in cls.requests.itervalues():
      print r

class child(object):

  def __init__(self, handle):
    self.handle = handle
    self.asns = set()
    self.prefixes = set()
    self.validity = None

  children = {}

  @classmethod
  def add(cls, handle, prefix = None, asn = None, validity = None):
    if handle not in cls.children:
      cls.children[handle] = cls(handle)
    if prefix is not None:
      cls.children[handle].prefixes.add(prefix)
    if asn is not None:
      cls.children[handle].asns.add(asn)
    if validity is not None:
      cls.children[handle].validity = validity

  def __str__(self):
    return "%s %s %s %s" % (self.handle, self.validity,
                            ",".join(self.asns),
                            ",".join(self.prefixes))

  @classmethod
  def show(cls):
    for c in cls.children.itervalues():
      print c

def csv_open(filename, delimiter = "\t", dialect = None):
  return csv.reader(open(filename, "rb"), dialect = dialect, delimiter = delimiter)

# format:  p/n-m asn
for pnm, asn in csv_open(roa_csv_file):
  roa_request.add(asn = asn, prefix = pnm)

# childname date
for handle, date in csv_open(validity_csv_file):
  child.add(handle = handle, validity = date)

# childname p/n
for handle, pn in csv_open(prefixes_csv_file):
  child.add(handle = handle, prefix = pn)

# childname asn
for handle, asn in csv_open(asns_csv_file):
  child.add(handle = handle, asn = asn)

roa_request.show()

child.show()

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

