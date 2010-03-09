"""
This program is now the merger of three different tools: the old
myrpki.py script, the old myirbe.py script, and the newer setup.py CLI
tool.  As such, it is still in need of some cleanup, but the need to
provide a saner user interface is more urgent than internal code
prettiness at the moment.  In the long run, 90% of the code in this
file probably ought to move to well-designed library modules.

The rest of the documentation in this module comment is lifted from
the previous scripts, and needs revision.  Then again, all the
commands in this tool need documenting too....

===

Read an OpenSSL-style config file and a bunch of .csv files to find
out about parents and children and resources and ROA requests, oh my.
Run OpenSSL command line tool to construct BPKI certificates,
including cross-certification of other entities' BPKI certificates.

Package up all of the above as a single XML file which user can then
ship off to the IRBE.  If an XML file already exists, check it for
data coming back from the IRBE (principally PKCS #10 requests for our
BSC) and update it with current data.

The general idea here is that this one XML file contains all of the
data that needs to be exchanged as part of ordinary update operations;
each party updates it as necessary, then ships it to the other via
some secure channel: carrier pigeon, USB stick, gpg-protected email,
we don't really care.

This one program is written a little differently from all the other
Python RPKI programs.  This one program is intended to run as a
stand-alone script, without the other programs present.  It does
require a reasonably up-to-date version of the OpenSSL command line
tool (the one built as a side effect of building rcynic will do), but
it does -not- require POW or any Python libraries beyond what ships
with Python 2.5.  So this script uses xml.etree from the Python
standard libraries instead of lxml.etree, which sacrifices XML schema
validation support in favor of portability, and so forth.

To make things a little weirder, as a convenience to IRBE operators,
this script can itself be loaded as a Python module and invoked as
part of another program.  This requires a few minor contortions, but
avoids duplicating common code.

===

IRBE-side stuff for myrpki tools.

The basic model here is that each entity with resources to certify
runs the myrpki tool, but not all of them necessarily run their own
RPKi engines.  The entities that do run RPKI engines get data from the
entities they host via the XML files output by the myrpki tool.  Those
XML files are the input to this script, which uses them to do all the
work of constructing certificates, populating SQL databases, and so
forth.  A few operations (eg, BSC construction) generate data which
has to be shipped back to the resource holder, which we do by updating
the same XML file.

In essence, the XML files are a sneakernet (or email, or carrier
pigeon) communication channel between the resource holders and the
RPKI engine operators.

As a convenience, for the normal case where the RPKI engine operator
is itself a resource holder, this script also runs the myrpki script
directly to process the RPKI engine operator's own resources.

Note that, due to the back and forth nature of some of these
operations, it may take several cycles for data structures to stablize
and everything to reach a steady state.  This is normal.

====

$Id$

Copyright (C) 2009-2010  Internet Systems Consortium ("ISC")

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

from __future__ import with_statement

import subprocess, csv, re, os, getopt, sys, base64, time, glob, copy, warnings
import rpki.config, rpki.cli, rpki.sundial

try:
  from lxml.etree import Element, SubElement, ElementTree
  have_lxml = True
except ImportError:
  from xml.etree.ElementTree import Element, SubElement, ElementTree
  have_lxml = False



# Our XML namespace and protocol version.

namespace      = "http://www.hactrn.net/uris/rpki/myrpki/"
version        = "2"
namespaceQName = "{" + namespace + "}"

# Dialect for our use of CSV files, here to make it easy to change if
# your site needs to do something different.  See doc for the csv
# module in the Python standard libraries for details if you need to
# customize this.

csv_dialect = csv.get_dialect("excel-tab")

# Whether to include incomplete entries when rendering to XML.

allow_incomplete = False

# Whether to whine about incomplete entries while rendering to XML.

whine = False

class comma_set(set):
  """
  Minor customization of set(), to provide a print syntax.
  """

  def __str__(self):
    return ",".join(self)

class EntityDB(object):
  """
  Wrapper for entitydb path lookups.  Hmm, maybe some or all of the
  entitydb glob stuff should end up here too?  Later.
  """

  def __init__(self, cfg):
    self.dir = cfg.get("entitydb_dir", "entitydb")

  def __call__(self, *args):
    return os.path.join(self.dir, *args)

  def iterate(self, *args):
    return glob.iglob(os.path.join(self.dir, *args))

class roa_request(object):
  """
  Representation of a ROA request.
  """

  v4re = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+(-[0-9]+)?$", re.I)
  v6re = re.compile("^([0-9a-f]{0,4}:){0,15}[0-9a-f]{0,4}/[0-9]+(-[0-9]+)?$", re.I)

  def __init__(self, asn, group):
    self.asn = asn
    self.group = group
    self.v4 = comma_set()
    self.v6 = comma_set()

  def __repr__(self):
    s = "<%s asn %s group %s" % (self.__class__.__name__, self.asn, self.group)
    if self.v4:
      s += " v4 %s" % self.v4
    if self.v6:
      s += " v6 %s" % self.v6
    return s + ">"

  def add(self, prefix):
    """
    Add one prefix to this ROA request.
    """
    if self.v4re.match(prefix):
      self.v4.add(prefix)
    elif self.v6re.match(prefix):
      self.v6.add(prefix)
    else:
      raise RuntimeError, "Bad prefix syntax: %r" % (prefix,)

  def xml(self, e):
    """
    Generate XML element represeting representing this ROA request.
    """
    e = SubElement(e, "roa_request",
                   asn = self.asn,
                   v4 = str(self.v4),
                   v6 = str(self.v6))
    e.tail = "\n"

class roa_requests(dict):
  """
  Database of ROA requests.
  """

  def add(self, asn, group, prefix):
    """
    Add one <ASN, group, prefix> set to ROA request database.
    """
    key = (asn, group)
    if key not in self:
      self[key] = roa_request(asn, group)
    self[key].add(prefix)

  def xml(self, e):
    """
    Render ROA requests as XML elements.
    """
    for r in self.itervalues():
      r.xml(e)

  @classmethod
  def from_csv(cls, roa_csv_file):
    """
    Parse ROA requests from CSV file.
    """
    self = cls()
    # format:  p/n-m asn group
    for pnm, asn, group in csv_open(roa_csv_file):
      self.add(asn = asn, group = group, prefix = pnm)
    return self

class child(object):
  """
  Representation of one child entity.
  """

  v4re = re.compile("^(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+)|(([0-9]{1,3}\.){3}[0-9]{1,3}-([0-9]{1,3}\.){3}[0-9]{1,3})$", re.I)
  v6re = re.compile("^(([0-9a-f]{0,4}:){0,15}[0-9a-f]{0,4}/[0-9]+)|(([0-9a-f]{0,4}:){0,15}[0-9a-f]{0,4}-([0-9a-f]{0,4}:){0,15}[0-9a-f]{0,4})$", re.I)

  def __init__(self, handle):
    self.handle = handle
    self.asns = comma_set()
    self.v4 = comma_set()
    self.v6 = comma_set()
    self.validity = None
    self.bpki_certificate = None

  def __repr__(self):
    s = "<%s %s" % (self.__class__.__name__, self.handle)
    if self.asns:
      s += " asn %s" % self.asns
    if self.v4:
      s += " v4 %s" % self.v4
    if self.v6:
      s += " v6 %s" % self.v6
    if self.validity:
      s += " valid %s" % self.validity
    if self.bpki_certificate:
      s += " cert %s" % self.bpki_certificate
    return s + ">"

  def add(self, prefix = None, asn = None, validity = None, bpki_certificate = None):
    """
    Add prefix, autonomous system number, validity date, or BPKI
    certificate for this child.
    """
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
    if bpki_certificate is not None:
      self.bpki_certificate = bpki_certificate

  def xml(self, e):
    """
    Render this child as an XML element.
    """
    complete = self.bpki_certificate and self.validity
    if whine and not complete:
      print "Incomplete child entry %s" % self
    if complete or allow_incomplete:
      e = SubElement(e, "child",
                     handle = self.handle,
                     valid_until = self.validity,
                     asns = str(self.asns),
                     v4 = str(self.v4),
                     v6 = str(self.v6))
      e.tail = "\n"
      if self.bpki_certificate:
        PEMElement(e, "bpki_certificate", self.bpki_certificate)

class children(dict):
  """
  Database of children.
  """

  def add(self, handle, prefix = None, asn = None, validity = None, bpki_certificate = None):
    """
    Add resources to a child, creating the child object if necessary.
    """
    if handle not in self:
      self[handle] = child(handle)
    self[handle].add(prefix = prefix, asn = asn, validity = validity, bpki_certificate = bpki_certificate)

  def xml(self, e):
    """
    Render children database to XML.
    """
    for c in self.itervalues():
      c.xml(e)

  @classmethod
  def from_csv(cls, children_csv_file, prefix_csv_file, asn_csv_file, fxcert, entitydb):
    """
    Parse child resources, certificates, and validity dates from CSV files.
    """
    self = cls()
    for f in entitydb.iterate("children", "*.xml"):
      c = etree_read(f)
      self.add(handle = os.path.splitext(os.path.split(f)[-1])[0],
               validity = c.get("valid_until"),
               bpki_certificate = fxcert(c.findtext("bpki_child_ta")))
    # childname p/n
    for handle, pn in csv_open(prefix_csv_file):
      self.add(handle = handle, prefix = pn)
    # childname asn
    for handle, asn in csv_open(asn_csv_file):
      self.add(handle = handle, asn = asn)
    return self

class parent(object):
  """
  Representation of one parent entity.
  """

  def __init__(self, handle):
    self.handle = handle
    self.service_uri = None
    self.bpki_cms_certificate = None
    self.bpki_https_certificate = None
    self.myhandle = None
    self.sia_base = None

  def __repr__(self):
    s = "<%s %s" % (self.__class__.__name__, self.handle)
    if self.myhandle:
      s += " myhandle %s" % self.myhandle
    if self.service_uri:
      s += " uri %s" % self.service_uri
    if self.sia_base:
      s += " sia %s" % self.sia_base
    if self.bpki_cms_certificate:
      s += " cms %s" % self.bpki_cms_certificate
    if self.bpki_https_certificate:
      s += " https %s" % self.bpki_https_certificate
    return s + ">"

  def add(self, service_uri = None,
          bpki_cms_certificate = None,
          bpki_https_certificate = None,
          myhandle = None,
          sia_base = None):
    """
    Add service URI or BPKI certificates to this parent object.
    """
    if service_uri is not None:
      self.service_uri = service_uri
    if bpki_cms_certificate is not None:
      self.bpki_cms_certificate = bpki_cms_certificate
    if bpki_https_certificate is not None:
      self.bpki_https_certificate = bpki_https_certificate
    if myhandle is not None:
      self.myhandle = myhandle
    if sia_base is not None:
      self.sia_base = sia_base

  def xml(self, e):
    """
    Render this parent object to XML.
    """
    complete = self.bpki_cms_certificate and self.bpki_https_certificate and self.myhandle and self.service_uri and self.sia_base
    if whine and not complete:
      print "Incomplete parent entry %s" % self
    if complete or allow_incomplete:
      e = SubElement(e, "parent",
                     handle = self.handle,
                     myhandle = self.myhandle,
                     service_uri = self.service_uri,
                     sia_base = self.sia_base)
      e.tail = "\n"
      if self.bpki_cms_certificate:
        PEMElement(e, "bpki_cms_certificate", self.bpki_cms_certificate)
      if self.bpki_https_certificate:
        PEMElement(e, "bpki_https_certificate", self.bpki_https_certificate)

class parents(dict):
  """
  Database of parent objects.
  """

  def add(self, handle,
          service_uri = None,
          bpki_cms_certificate = None,
          bpki_https_certificate = None,
          myhandle = None,
          sia_base = None):
    """
    Add service URI or certificates to parent object, creating it if necessary.
    """
    if handle not in self:
      self[handle] = parent(handle)
    self[handle].add(service_uri = service_uri,
                     bpki_cms_certificate = bpki_cms_certificate,
                     bpki_https_certificate = bpki_https_certificate,
                     myhandle = myhandle,
                     sia_base = sia_base)

  def xml(self, e):
    for c in self.itervalues():
      c.xml(e)

  @classmethod
  def from_csv(cls, fxcert, entitydb):
    """
    Parse parent data from entitydb.
    """
    self = cls()
    for f in entitydb.iterate("parents", "*.xml"):
      h = os.path.splitext(os.path.split(f)[-1])[0]
      p = etree_read(f)
      r = etree_read(f.replace(os.path.sep + "parents"      + os.path.sep,
                               os.path.sep + "repositories" + os.path.sep))
      assert r.get("type") == "confirmed"
      self.add(handle = h,
               service_uri = p.get("service_uri"),
               bpki_cms_certificate = fxcert(p.findtext("bpki_resource_ta")),
               bpki_https_certificate = fxcert(p.findtext("bpki_server_ta")),
               myhandle = p.get("child_handle"),
               sia_base = r.get("sia_base"))
    return self

class repository(object):
  """
  Representation of one repository entity.
  """

  def __init__(self, handle):
    self.handle = handle
    self.service_uri = None
    self.bpki_certificate = None

  def __repr__(self):
    s = "<%s %s" % (self.__class__.__name__, self.handle)
    if self.service_uri:
      s += " uri %s" % self.service_uri
    if self.bpki_certificate:
      s += " cert %s" % self.bpki_certificate
    return s + ">"

  def add(self, service_uri = None, bpki_certificate = None):
    """
    Add service URI or BPKI certificates to this repository object.
    """
    if service_uri is not None:
      self.service_uri = service_uri
    if bpki_certificate is not None:
      self.bpki_certificate = bpki_certificate

  def xml(self, e):
    """
    Render this repository object to XML.
    """
    complete = self.bpki_certificate and self.service_uri
    if whine and not complete:
      print "Incomplete repository entry %s" % self
    if complete or allow_incomplete:
      e = SubElement(e, "repository",
                     handle = self.handle,
                     service_uri = self.service_uri)
      e.tail = "\n"
      if self.bpki_certificate:
        PEMElement(e, "bpki_certificate", self.bpki_certificate)

class repositories(dict):
  """
  Database of repository objects.
  """

  def add(self, handle,
          service_uri = None,
          bpki_certificate = None):
    """
    Add service URI or certificate to repository object, creating it if necessary.
    """
    if handle not in self:
      self[handle] = repository(handle)
    self[handle].add(service_uri = service_uri,
                     bpki_certificate = bpki_certificate)

  def xml(self, e):
    for c in self.itervalues():
      c.xml(e)

  @classmethod
  def from_csv(cls, fxcert, entitydb):
    """
    Parse repository data from entitydb.
    """
    self = cls()
    for f in entitydb.iterate("repositories", "*.xml"):
      h = os.path.splitext(os.path.split(f)[-1])[0]
      r = etree_read(f)
      assert r.get("type") == "confirmed"
      self.add(handle = h,
               service_uri = r.get("service_uri"),
               bpki_certificate = fxcert(r.findtext("bpki_server_ta")))
    return self

def csv_open(filename):
  """
  Open a CSV file, with settings that make it a tab-delimited file.
  You may need to tweak this function for your environment, see the
  csv module in the Python standard libraries for details.
  """
  return csv.reader(open(filename, "rb"), dialect = csv_dialect)

def PEMElement(e, tag, filename, **kwargs):
  """
  Create an XML element containing Base64 encoded data taken from a
  PEM file.
  """
  lines = open(filename).readlines()
  while lines:
    if lines.pop(0).startswith("-----BEGIN "):
      break
  while lines:
    if lines.pop(-1).startswith("-----END "):
      break
  if e.text is None:
    e.text = "\n"
  se = SubElement(e, tag, **kwargs)
  se.text = "\n" + "".join(lines)
  se.tail = "\n"
  return se

class CA(object):
  """
  Representation of one certification authority.
  """

  # Mapping of path restriction values we use to OpenSSL config file
  # section names.

  path_restriction = { 0 : "ca_x509_ext_xcert0",
                       1 : "ca_x509_ext_xcert1" }

  def __init__(self, cfg, dir):
    self.cfg    = cfg
    self.dir    = dir
    self.cer    = dir + "/ca.cer"
    self.key    = dir + "/ca.key"
    self.req    = dir + "/ca.req"
    self.crl    = dir + "/ca.crl"
    self.index  = dir + "/index"
    self.serial = dir + "/serial"
    self.crlnum = dir + "/crl_number"

    self.env = { "PATH" : os.environ["PATH"],
                 "BPKI_DIRECTORY" : dir,
                 "RANDFILE" : ".OpenSSL.whines.unless.I.set.this" }

  def run_ca(self, *args):
    """
    Run OpenSSL "ca" command with tailored environment variables and common initial
    arguments.  "ca" is rather chatty, so we suppress its output except on errors.
    """
    cmd = (openssl, "ca", "-batch", "-config",  self.cfg) + args
    p = subprocess.Popen(cmd, env = self.env, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    log = p.communicate()[0]
    if p.wait() != 0:
      sys.stderr.write(log)
      raise subprocess.CalledProcessError(returncode = p.returncode, cmd = cmd)

  def run_req(self, key_file, req_file):
    """
    Run OpenSSL "req" command with tailored environment variables and common arguments.
    "req" is rather chatty, so we suppress its output except on errors.
    """
    if not os.path.exists(key_file) or not os.path.exists(req_file):
      cmd = (openssl, "req", "-new", "-sha256", "-newkey", "rsa:2048",
             "-config", self.cfg, "-keyout", key_file, "-out", req_file)
      p = subprocess.Popen(cmd, env = self.env, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
      log = p.communicate()[0]
      if p.wait() != 0:
        sys.stderr.write(log)
        raise subprocess.CalledProcessError(returncode = p.returncode, cmd = cmd)

  @staticmethod
  def touch_file(filename, content = None):
    """
    Create dumb little text files expected by OpenSSL "ca" utility.
    """
    if not os.path.exists(filename):
      f = open(filename, "w")
      if content is not None:
        f.write(content)
      f.close()

  def setup(self, ca_name):
    """
    Set up this CA.  ca_name is an X.509 distinguished name in
    /tag=val/tag=val format.
    """

    modified = False

    if not os.path.exists(self.dir):
      os.makedirs(self.dir)
      self.touch_file(self.index)
      self.touch_file(self.serial, "01\n")
      self.touch_file(self.crlnum, "01\n")

    self.run_req(key_file = self.key, req_file = self.req)

    if not os.path.exists(self.cer):
      modified = True
      self.run_ca("-selfsign", "-extensions", "ca_x509_ext_ca", "-subj", ca_name, "-in", self.req, "-out", self.cer)

    if not os.path.exists(self.crl):
      modified = True
      self.run_ca("-gencrl", "-out", self.crl)

    return modified

  def ee(self, ee_name, base_name):
    """
    Issue an end-enity certificate.
    """
    key_file = "%s/%s.key" % (self.dir, base_name)
    req_file = "%s/%s.req" % (self.dir, base_name)
    cer_file = "%s/%s.cer" % (self.dir, base_name)
    self.run_req(key_file = key_file, req_file = req_file)
    if not os.path.exists(cer_file):
      self.run_ca("-extensions", "ca_x509_ext_ee", "-subj", ee_name, "-in", req_file, "-out", cer_file)
      return True
    else:
      return False

  def bsc(self, pkcs10):
    """
    Issue BSC certificiate, if we have a PKCS #10 request for it.
    """

    if pkcs10 is None:
      return None, None
    
    pkcs10 = base64.b64decode(pkcs10)

    assert pkcs10

    cmd = (openssl, "dgst", "-md5")
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE)
    hash = p.communicate(pkcs10)[0].strip()
    if p.wait() != 0:
      raise subprocess.CalledProcessError(returncode = p.returncode, cmd = cmd)

    req_file = "%s/bsc.%s.req" % (self.dir, hash)
    cer_file = "%s/bsc.%s.cer" % (self.dir, hash)

    if not os.path.exists(cer_file):

      cmd = (openssl, "req", "-inform", "DER", "-out", req_file)
      p = subprocess.Popen(cmd, stdin = subprocess.PIPE)
      p.communicate(pkcs10)
      if p.wait() != 0:
        raise subprocess.CalledProcessError(returncode = p.returncode, cmd = cmd)

      self.run_ca("-extensions", "ca_x509_ext_ee", "-in", req_file, "-out", cer_file)

    return req_file, cer_file

  def fxcert(self, b64, filename = None, path_restriction = 0):
    """
    Write PEM certificate to file, then cross-certify.
    """
    fn = os.path.join(self.dir, filename or "temp.%s.cer" % os.getpid())
    try:
      cmd = (openssl, "x509", "-inform", "DER", "-out", fn)
      p = subprocess.Popen(cmd, stdin = subprocess.PIPE)
      p.communicate(base64.b64decode(b64))
      if p.wait() != 0:
        raise subprocess.CalledProcessError(returncode = p.returncode, cmd = cmd)
      return self.xcert(fn, path_restriction)
    finally:
      if not filename and os.path.exists(fn):
        #os.unlink(fn)
        pass

  def xcert(self, cert, path_restriction = 0):
    """
    Cross-certify a certificate represented as a PEM file.
    """

    if not cert:
      return None

    if not os.path.exists(cert):
      #print "Certificate %s doesn't exist, skipping" % cert
      return None

    # Extract public key and subject name from PEM file and hash it so
    # we can use the result as a tag for cross-certifying this cert.

    cmd1 = (openssl, "x509", "-noout", "-pubkey", "-subject", "-in", cert)
    cmd2 = (openssl, "dgst", "-md5")

    p1 = subprocess.Popen(cmd1, stdout = subprocess.PIPE)
    p2 = subprocess.Popen(cmd2, stdin = p1.stdout, stdout = subprocess.PIPE)

    xcert = "%s/xcert.%s.cer" % (self.dir, p2.communicate()[0].strip())

    if p1.wait() != 0:
      raise subprocess.CalledProcessError(returncode = p1.returncode, cmd = cmd1)
    if p2.wait() != 0:
      raise subprocess.CalledProcessError(returncode = p2.returncode, cmd = cmd2)

    # Cross-certify the cert we were given, if we haven't already.
    # This only works for self-signed certs, due to limitations of the
    # OpenSSL command line tool, but that suffices for our purposes.

    if not os.path.exists(xcert):
      self.run_ca("-ss_cert", cert, "-out", xcert, "-extensions", self.path_restriction[path_restriction])

    return xcert

def etree_validate(e):
  # This is a kludge, schema should be loaded as module or configured
  # in .conf, but it will do as a temporary debugging hack.
  schema = os.getenv("MYRPKI_RNG")
  if schema:
    try:
      import lxml.etree
    except ImportError:
      return
    try:
      lxml.etree.RelaxNG(file = schema).assertValid(e)
    except lxml.etree.RelaxNGParseError:
      return
    except lxml.etree.DocumentInvalid:
      print lxml.etree.tostring(e, pretty_print = True)
      raise

def etree_write(e, filename, verbose = True, validate = False):
  """
  Write out an etree to a file, safely.

  I still miss SYSCAL(RENMWO).
  """
  assert isinstance(filename, str)
  if verbose:
    print "Writing", filename
  e = copy.deepcopy(e)
  e.set("version", version)
  for i in e.getiterator():
    if i.tag[0] != "{":
      i.tag = namespaceQName + i.tag
    assert i.tag.startswith(namespaceQName)
  if validate:
    etree_validate(e)
  ElementTree(e).write(filename + ".tmp")
  os.rename(filename + ".tmp", filename)

def etree_read(filename, verbose = False, validate = False):
  """
  Read an etree from a file, verifying then stripping XML namespace
  cruft.
  """
  if verbose:
    print "Reading", filename
  e = ElementTree(file = filename).getroot()
  if validate:
    etree_validate(e)
  for i in e.getiterator():
    if i.tag.startswith(namespaceQName):
      i.tag = i.tag[len(namespaceQName):]
    else:
      raise RuntimeError, "XML tag %r is not in namespace %r" % (i.tag, namespace)
  return e

# When this file is run as a script, run main() with command line
# arguments.  main() can't use sys.argv directly as that might be the
# command line for some other program that loads this module.



class main(rpki.cli.Cmd):

  prompt = "setup> "

  completedefault = rpki.cli.Cmd.filename_complete


  def __init__(self):
    os.environ["TZ"] = "UTC"
    time.tzset()

    self.cfg_file = os.getenv("MYRPKI_CONF", "myrpki.conf")

    opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
    for o, a in opts:
      if o in ("-c", "--config"):
        self.cfg_file = a
      elif o in ("-h", "--help", "-?"):
        argv = ["help"]

    if not argv or argv[0] != "help":
      self.read_config()

    rpki.cli.Cmd.__init__(self, argv)


  def read_config(self):

    self.cfg = rpki.config.parser(self.cfg_file, "myrpki")

    global openssl
    openssl  = self.cfg.get("openssl", "openssl")

    self.histfile  = self.cfg.get("history_file", ".setup_history")
    self.handle    = self.cfg.get("handle")
    self.run_rpkid = self.cfg.getboolean("run_rpkid")
    self.run_pubd  = self.cfg.getboolean("run_pubd")
    self.run_rootd = self.cfg.getboolean("run_rootd")
    self.entitydb  = EntityDB(self.cfg)

    if self.run_rootd and (not self.run_pubd or not self.run_rpkid):
      raise RuntimeError, "Can't run rootd unless also running rpkid and pubd"

    self.bpki_resources = CA(self.cfg_file, self.cfg.get("bpki_resources_directory"))
    if self.run_rpkid or self.run_pubd or self.run_rootd:
      self.bpki_servers = CA(self.cfg_file, self.cfg.get("bpki_servers_directory"))

    self.pubd_contact_info = self.cfg.get("pubd_contact_info", "")

    self.rsync_module = self.cfg.get("publication_rsync_module")
    self.rsync_server = self.cfg.get("publication_rsync_server")


  def do_initialize(self, arg):
    if arg:
      raise RuntimeError, "This command takes no arguments"

    print "Generating RSA keys, this may take a little while..."

    self.bpki_resources.setup(self.cfg.get("bpki_resources_ta_dn",
                                           "/CN=%s BPKI Resource Trust Anchor" % self.handle))
    if self.run_rpkid or self.run_pubd or self.run_rootd:
      self.bpki_servers.setup(self.cfg.get("bpki_servers_ta_dn",
                                           "/CN=%s BPKI Server Trust Anchor" % self.handle))

    # Create entitydb directories.

    for i in ("parents", "children", "repositories", "pubclients"):
      d = self.entitydb(i)
      if not os.path.exists(d):
        os.makedirs(d)

    if self.run_rpkid or self.run_pubd or self.run_rootd:

      if self.run_rpkid:
        self.bpki_servers.ee(self.cfg.get("bpki_rpkid_ee_dn",
                                          "/CN=%s rpkid server certificate" % self.handle), "rpkid")
        self.bpki_servers.ee(self.cfg.get("bpki_irdbd_ee_dn",
                                          "/CN=%s irdbd server certificate" % self.handle), "irdbd")
      if self.run_pubd:
        self.bpki_servers.ee(self.cfg.get("bpki_pubd_ee_dn",
                                          "/CN=%s pubd server certificate" % self.handle), "pubd")
      if self.run_rpkid or self.run_pubd:
        self.bpki_servers.ee(self.cfg.get("bpki_irbe_ee_dn",
                                          "/CN=%s irbe client certificate" % self.handle), "irbe")
      if self.run_rootd:
        self.bpki_servers.ee(self.cfg.get("bpki_rootd_ee_dn",
                                          "/CN=%s rootd server certificate" % self.handle), "rootd")

    # Build the identity.xml file.  Need to check for existing file so we don't
    # overwrite?  Worry about that later.

    e = Element("identity", handle = self.handle)
    PEMElement(e, "bpki_ta", self.bpki_resources.cer)
    etree_write(e, self.entitydb("identity.xml"))

    # If we're running rootd, construct a fake parent to go with it,
    # and cross-certify in both directions so we can talk to rootd.

    if self.run_rootd:

      e = Element("parent", parent_handle = self.handle, child_handle = self.handle,
                  service_uri = "https://localhost:%s/" % self.cfg.get("rootd_server_port"),
                  valid_until = str(rpki.sundial.now() + rpki.sundial.timedelta(days = 365)))
      PEMElement(e, "bpki_resource_ta", self.bpki_servers.cer)
      PEMElement(e, "bpki_server_ta", self.bpki_servers.cer)
      PEMElement(e, "bpki_child_ta", self.bpki_resources.cer)
      SubElement(e, "repository", type = "offer")
      etree_write(e, self.entitydb("parents", "%s.xml" % self.handle))

      self.bpki_resources.xcert(self.bpki_servers.cer)

      rootd_child_fn = self.cfg.get("child-bpki-cert", None, "rootd")
      if not os.path.exists(rootd_child_fn):
        os.link(self.bpki_servers.xcert(self.bpki_resources.cer), rootd_child_fn)

    # If we're running pubd, construct repository request for it, as
    # if we had received an offer.

    if self.run_pubd:
      e = Element("repository", type = "request", handle = self.handle, parent_handle = self.handle)
      SubElement(e, "contact_info").text = self.pubd_contact_info
      PEMElement(e, "bpki_ta", self.bpki_resources.cer)
      etree_write(e, self.entitydb("repositories", "%s.xml" % self.handle))


  def do_answer_child(self, arg):

    child_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["child_handle="])
    for o, a in opts:
      if o == "--child_handle":
        child_handle = a
    
    if len(argv) != 1:
      raise RuntimeError, "Need to specify filename for child.xml"

    if not self.run_rpkid:
      raise RuntimeError, "Don't (yet) know how to set up child unless we run rpkid"

    c = etree_read(argv[0])

    if child_handle is None:
      child_handle = c.get("handle")

    print "Child calls itself %r, we call it %r" % (c.get("handle"), child_handle)

    self.bpki_servers.fxcert(c.findtext("bpki_ta"))

    e = Element("parent", parent_handle = self.handle, child_handle = child_handle,
                service_uri = "https://%s:%s/up-down/%s/%s" % (self.cfg.get("rpkid_server_host"),
                                                               self.cfg.get("rpkid_server_port"),
                                                               self.handle, child_handle),
                valid_until = str(rpki.sundial.now() + rpki.sundial.timedelta(days = 365)))

    PEMElement(e, "bpki_resource_ta", self.bpki_resources.cer)
    PEMElement(e, "bpki_server_ta",   self.bpki_servers.cer)
    SubElement(e, "bpki_child_ta").text = c.findtext("bpki_ta")

    try:
      repo = None
      for f in self.entitydb.iterate("repositories", "*.xml"):
        r = etree_read(f)
        if r.get("type") == "confirmed":
          if repo is not None:
            raise RuntimeError, "Too many repositories, I don't know what to do, not giving referral"
          repo_handle = os.path.splitext(os.path.split(f)[-1])[0]
          repo = r
      if repo is None:
        raise RuntimeError, "Couldn't find any usable repositories, not giving referral"

      if repo_handle == self.handle:
        SubElement(e, "repository", type = "offer")
      else:
        r = SubElement(e, "repository", type = "hint",
                       proposed_sia_base = repo.get("sia_base") + child_handle + "/")
        SubElement(r, "contact_info").text = repo.findtext("contact_info")
        # CMS-signed blob authorizing use of part of our space by our
        # child goes here, once I've written that code.

    except RuntimeError, err:
      print err

    etree_write(e, self.entitydb("children", "%s.xml" % child_handle))


  def do_process_parent_answer(self, arg):

    parent_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["parent_handle="])
    for o, a in opts:
      if o == "--parent_handle":
        parent_handle = a

    if len(argv) != 1:
      raise RuntimeError, "Need to specify filename for parent.xml on command line"

    p = etree_read(argv[0])

    if parent_handle is None:
      parent_handle = p.get("parent_handle")

    print "Parent calls itself %r, we call it %r" % (p.get("parent_handle"), parent_handle)
    print "Parent calls us %r" % p.get("child_handle")

    self.bpki_resources.fxcert(p.findtext("bpki_resource_ta"))
    self.bpki_resources.fxcert(p.findtext("bpki_server_ta"))

    etree_write(p, self.entitydb("parents", "%s.xml" % parent_handle))

    r = p.find("repository")

    if r is not None and r.get("type") in ("offer", "hint"):
      r.set("handle", self.handle)
      r.set("parent_handle", parent_handle)
      PEMElement(r, "bpki_ta", self.bpki_resources.cer)
      etree_write(r, self.entitydb("repositories", "%s.xml" % parent_handle))

    else:
      print "Couldn't find repository offer or hint"


  def do_answer_repository_client(self, arg):

    sia_base = None

    opts, argv = getopt.getopt(arg.split(), "", ["sia_base="])
    for o, a in opts:
      if o == "--sia_base":
        sia_base = a
    
    if len(argv) != 1:
      raise RuntimeError, "Need to specify filename for client.xml"

    c = etree_read(argv[0])

    # Critical thing at this point is to figure out what client's
    # sia_base value should be.  Three cases:
    #
    # - client has no particular relationship to any other client:
    #   sia_base is top-level, or as close as we can make it taking
    #   rsyncd module into account (maybe homed under us, hmm, how do
    #   we detect case where we are talking to ourself?)
    #
    # - client is a direct child of ours to whom we (in our parent
    #   role) made an offer of publication service.  client homes
    #   under us, presumably.
    #
    # - client is a child of a client of ours who referred the new
    #   client to us, along with a signed referral.  signed referral
    #   includes sia_base of referring client, new client homes under
    #   that per referring client's wishes.
    #
    # ... which implies that there's a fourth case, where we are both
    # the client and the server.

    # Checking of signed referrals goes somewhere around here.  Must
    # be after reading client's XML, but before deciding what the
    # client's sia_base and handle will be.

    # For the moment we cheat egregiously, no crypto, blind trust of
    # what we're sent, while I focus on the basic semantics.

    if sia_base is None and c.get("proposed_sia_base"):
      sia_base = c.get("proposed_sia_base")
    elif sia_base is None and c.get("handle") == self.handle:
      sia_base = "rsync://%s/%s/" % (self.rsync_server, self.rsync_module)
    else:
      sia_base = "rsync://%s/%s/%s/" % (self.rsync_server, self.rsync_module, c.get("handle"))

    client_handle = "/".join(sia_base.rstrip("/").split("/")[3:])

    parent_handle = c.get("parent_handle")

    print "Client calls itself %r, we call it %r" % (c.get("handle"), client_handle)
    print "Client says its parent handle is %r" % parent_handle

    self.bpki_servers.fxcert(c.findtext("bpki_ta"))

    e = Element("repository", type = "confirmed",
                repository_handle = self.handle,
                client_handle = client_handle,
                parent_handle = parent_handle,
                sia_base = sia_base,
                service_uri = "https://%s:%s/client/%s" % (self.cfg.get("pubd_server_host"),
                                                           self.cfg.get("pubd_server_port"),
                                                           client_handle))

    PEMElement(e, "bpki_server_ta", self.bpki_servers.cer)
    SubElement(e, "bpki_client_ta").text = c.findtext("bpki_ta")
    SubElement(e, "contact_info").text = self.pubd_contact_info
    etree_write(e, self.entitydb("pubclients", "%s.xml" % client_handle.replace("/", ".")))


  def do_process_repository_answer(self, arg):

    argv = arg.split()

    if len(argv) != 1:
      raise RuntimeError, "Need to specify filename for repository.xml on command line"

    r = etree_read(argv[0])

    parent_handle = r.get("parent_handle")

    print "Repository calls itself %r, calls us %r" % (r.get("repository_handle"), r.get("client_handle"))
    print "Repository response associated with parent_handle %r" % parent_handle

    etree_write(r, self.entitydb("repositories", "%s.xml" % parent_handle))


  def do_compose_request_to_host(self, arg):
    pass

  def do_answer_hosted_entity(self, arg):
    pass

  def do_process_host_answer(self, arg):
    pass




  def myrpki_main(self):
    """
    Main program of old myrpki.py script.
    """

    roa_csv_file                  = self.cfg.get("roa_csv")
    children_csv_file             = self.cfg.get("children_csv")
    prefix_csv_file               = self.cfg.get("prefix_csv")
    asn_csv_file                  = self.cfg.get("asn_csv")

    # This probably should become an argument instead of (or in
    # addition to a default from?) config file.
    xml_filename                  = self.cfg.get("xml_filename")

    try:
      bsc_req, bsc_cer = self.bpki_resources.bsc(etree_read(xml_filename).findtext("bpki_bsc_pkcs10"))
    except IOError:
      bsc_req, bsc_cer = None, None

    e = Element("myrpki", handle = self.handle)

    roa_requests.from_csv(roa_csv_file).xml(e)

    children.from_csv(
      children_csv_file = children_csv_file,
      prefix_csv_file = prefix_csv_file,
      asn_csv_file = asn_csv_file,
      fxcert = self.bpki_resources.fxcert,
      entitydb = self.entitydb).xml(e)

    parents.from_csv(     fxcert = self.bpki_resources.fxcert, entitydb = self.entitydb).xml(e)
    repositories.from_csv(fxcert = self.bpki_resources.fxcert, entitydb = self.entitydb).xml(e)

    PEMElement(e, "bpki_ca_certificate", self.bpki_resources.cer)
    PEMElement(e, "bpki_crl",            self.bpki_resources.crl)

    if bsc_cer:
      PEMElement(e, "bpki_bsc_certificate", bsc_cer)

    if bsc_req:
      PEMElement(e, "bpki_bsc_pkcs10", bsc_req)

    etree_write(e, xml_filename)


  def do_myrpki(self, arg):
    if arg:
      raise RuntimeError, "Unexpected argument %r" % arg
    self.myrpki_main()



  def myirbe_main(self, argv = []):
    """
    Main program of old myirbe.py script.
    """

    import rpki.https, rpki.resource_set, rpki.relaxng, rpki.exceptions
    import rpki.left_right, rpki.log, rpki.x509, rpki.async

    # Silence warning while loading MySQLdb in Python 2.6, sigh
    if hasattr(warnings, "catch_warnings"):
      with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import MySQLdb
    else:
      import MySQLdb

    def findbase64(tree, name, b64type = rpki.x509.X509):
      """
      Find and extract a base64-encoded XML element, if present.
      """
      x = tree.findtext(name)
      return b64type(Base64 = x) if x else None

    # For simple cases we don't really care what this value is, so long as
    # we're consistant about it, so wiring this in is fine.

    bsc_handle = "bsc"

    rpki.log.init("myirbe")

    self.cfg.set_global_flags()

    # Default values for CRL parameters are low, for testing.  Not
    # quite as low as they once were, too much expired CRL whining.

    self_crl_interval = self.cfg.getint("self_crl_interval", 2 * 60 * 60)
    self_regen_margin = self.cfg.getint("self_regen_margin", 30 * 60)
    pubd_base         = self.cfg.get("pubd_base").rstrip("/") + "/"
    rpkid_base        = self.cfg.get("rpkid_base").rstrip("/") + "/"

    # Nasty regexp for parsing rpkid's up-down service URLs.

    updown_regexp = re.compile(re.escape(rpkid_base) + "up-down/([-A-Z0-9_]+)/([-A-Z0-9_]+)$", re.I)

    # Wrappers to simplify calling rpkid and pubd.

    call_rpkid = rpki.async.sync_wrapper(rpki.https.caller(
      proto       = rpki.left_right,
      client_key  = rpki.x509.RSA( PEM_file = self.bpki_servers.dir + "/irbe.key"),
      client_cert = rpki.x509.X509(PEM_file = self.bpki_servers.dir + "/irbe.cer"),
      server_ta   = rpki.x509.X509(PEM_file = self.bpki_servers.cer),
      server_cert = rpki.x509.X509(PEM_file = self.bpki_servers.dir + "/rpkid.cer"),
      url         = rpkid_base + "left-right",
      debug       = True))

    if self.run_pubd:

      call_pubd = rpki.async.sync_wrapper(rpki.https.caller(
        proto       = rpki.publication,
        client_key  = rpki.x509.RSA( PEM_file = self.bpki_servers.dir + "/irbe.key"),
        client_cert = rpki.x509.X509(PEM_file = self.bpki_servers.dir + "/irbe.cer"),
        server_ta   = rpki.x509.X509(PEM_file = self.bpki_servers.cer),
        server_cert = rpki.x509.X509(PEM_file = self.bpki_servers.dir + "/pubd.cer"),
        url         = pubd_base + "control",
        debug       = True))

      # Make sure that pubd's BPKI CRL is up to date.

      call_pubd(rpki.publication.config_elt.make_pdu(
        action = "set",
        bpki_crl = rpki.x509.CRL(PEM_file = self.bpki_servers.crl)))

    irdbd_cfg = rpki.config.parser(self.cfg.get("irdbd_conf", self.cfg_file), "irdbd")

    db = MySQLdb.connect(user   = irdbd_cfg.get("sql-username"),
                         db     = irdbd_cfg.get("sql-database"),
                         passwd = irdbd_cfg.get("sql-password"))

    cur = db.cursor()

    xmlfiles = []

    # If [myrpki] section includes an "xml_filename" setting, run
    # myrpki.py internally, as a convenience, and include its output at
    # the head of our list of XML files to process.

    my_xmlfile = self.cfg.get("xml_filename", "")
    if my_xmlfile:
      self.myrpki_main()
      xmlfiles.append(my_xmlfile)
    else:
      my_xmlfile = None

    # Add any other XML files specified on the command line

    xmlfiles.extend(argv)

    my_handle = None

    for xmlfile in xmlfiles:

      # Parse XML file and validate it against our scheme

      tree = etree_read(xmlfile, validate = True)

      handle = tree.get("handle")

      if xmlfile == my_xmlfile:
        my_handle = handle

      # Update IRDB with parsed resource and roa-request data.

      cur.execute(
        """
        DELETE
        FROM  roa_request_prefix
        USING roa_request, roa_request_prefix
        WHERE roa_request.roa_request_id = roa_request_prefix.roa_request_id AND roa_request.roa_request_handle = %s
        """, (handle,))

      cur.execute("DELETE FROM roa_request WHERE roa_request.roa_request_handle = %s", (handle,))

      for x in tree.getiterator("roa_request"):
        cur.execute("INSERT roa_request (roa_request_handle, asn) VALUES (%s, %s)", (handle, x.get("asn")))
        roa_request_id = cur.lastrowid
        for version, prefix_set in ((4, rpki.resource_set.roa_prefix_set_ipv4(x.get("v4"))), (6, rpki.resource_set.roa_prefix_set_ipv6(x.get("v6")))):
          if prefix_set:
            cur.executemany("INSERT roa_request_prefix (roa_request_id, prefix, prefixlen, max_prefixlen, version) VALUES (%s, %s, %s, %s, %s)",
                            ((roa_request_id, p.prefix, p.prefixlen, p.max_prefixlen, version) for p in prefix_set))

      cur.execute(
        """
        DELETE
        FROM   registrant_asn
        USING registrant, registrant_asn
        WHERE registrant.registrant_id = registrant_asn.registrant_id AND registrant.registry_handle = %s
        """ , (handle,))

      cur.execute(
        """
        DELETE FROM registrant_net USING registrant, registrant_net
        WHERE registrant.registrant_id = registrant_net.registrant_id AND registrant.registry_handle = %s
        """ , (handle,))

      cur.execute("DELETE FROM registrant WHERE registrant.registry_handle = %s" , (handle,))

      for x in tree.getiterator("child"):
        child_handle = x.get("handle")
        asns = rpki.resource_set.resource_set_as(x.get("asns"))
        ipv4 = rpki.resource_set.resource_set_ipv4(x.get("v4"))
        ipv6 = rpki.resource_set.resource_set_ipv6(x.get("v6"))

        cur.execute("INSERT registrant (registrant_handle, registry_handle, registrant_name, valid_until) VALUES (%s, %s, %s, %s)",
                    (child_handle, handle, child_handle, rpki.sundial.datetime.fromXMLtime(x.get("valid_until")).to_sql()))
        child_id = cur.lastrowid
        if asns:
          cur.executemany("INSERT registrant_asn (start_as, end_as, registrant_id) VALUES (%s, %s, %s)",
                          ((a.min, a.max, child_id) for a in asns))
        if ipv4:
          cur.executemany("INSERT registrant_net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 4, %s)",
                          ((a.min, a.max, child_id) for a in ipv4))
        if ipv6:
          cur.executemany("INSERT registrant_net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 6, %s)",
                          ((a.min, a.max, child_id) for a in ipv6))

      db.commit()

      # Check for certificates before attempting anything else

      hosted_cacert = findbase64(tree, "bpki_ca_certificate")
      if not hosted_cacert:
        print "Nothing else I can do without a trust anchor for the entity I'm hosting."
        continue

      rpkid_xcert = rpki.x509.X509(PEM_file = self.bpki_servers.fxcert(b64 = hosted_cacert.get_Base64(),
                                                                       filename = handle + ".cacert.cer",
                                                                       path_restriction = 1))

      # See what rpkid and pubd already have on file for this entity.

      if self.run_pubd:
        client_pdus = dict((x.client_handle, x)
                           for x in call_pubd(rpki.publication.client_elt.make_pdu(action = "list"))
                           if isinstance(x, rpki.publication.client_elt))

      rpkid_reply = call_rpkid(
        rpki.left_right.self_elt.make_pdu(      action = "get",  tag = "self",       self_handle = handle),
        rpki.left_right.bsc_elt.make_pdu(       action = "list", tag = "bsc",        self_handle = handle),
        rpki.left_right.repository_elt.make_pdu(action = "list", tag = "repository", self_handle = handle),
        rpki.left_right.parent_elt.make_pdu(    action = "list", tag = "parent",     self_handle = handle),
        rpki.left_right.child_elt.make_pdu(     action = "list", tag = "child",      self_handle = handle))

      self_pdu        = rpkid_reply[0]
      bsc_pdus        = dict((x.bsc_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.bsc_elt))
      repository_pdus = dict((x.repository_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.repository_elt))
      parent_pdus     = dict((x.parent_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.parent_elt))
      child_pdus      = dict((x.child_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.child_elt))

      pubd_query = []
      rpkid_query = []

      # There should be exactly one <self/> object per hosted entity, by definition

      if (isinstance(self_pdu, rpki.left_right.report_error_elt) or
          self_pdu.crl_interval != self_crl_interval or
          self_pdu.regen_margin != self_regen_margin or
          self_pdu.bpki_cert != rpkid_xcert):
        rpkid_query.append(rpki.left_right.self_elt.make_pdu(
          action = "create" if isinstance(self_pdu, rpki.left_right.report_error_elt) else "set",
          tag = "self",
          self_handle = handle,
          bpki_cert = rpkid_xcert,
          crl_interval = self_crl_interval,
          regen_margin = self_regen_margin))

      # In general we only need one <bsc/> per <self/>.  BSC objects are a
      # little unusual in that the PKCS #10 subelement is generated by rpkid
      # in response to generate_keypair, so there's more of a separation
      # between create and set than with other objects.

      bsc_cert = findbase64(tree, "bpki_bsc_certificate")
      bsc_crl  = findbase64(tree, "bpki_crl", rpki.x509.CRL)

      bsc_pdu = bsc_pdus.pop(bsc_handle, None)

      if bsc_pdu is None:
        rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(
          action = "create",
          tag = "bsc",
          self_handle = handle,
          bsc_handle = bsc_handle,
          generate_keypair = "yes"))
      elif bsc_pdu.signing_cert != bsc_cert or bsc_pdu.signing_cert_crl != bsc_crl:
        rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(
          action = "set",
          tag = "bsc",
          self_handle = handle,
          bsc_handle = bsc_handle,
          signing_cert = bsc_cert,
          signing_cert_crl = bsc_crl))

      rpkid_query.extend(rpki.left_right.bsc_elt.make_pdu(
        action = "destroy", self_handle = handle, bsc_handle = b) for b in bsc_pdus)

      bsc_req = None

      if bsc_pdu and bsc_pdu.pkcs10_request:
        bsc_req = bsc_pdu.pkcs10_request

      # At present we need one <repository/> per <parent/>, not because
      # rpkid requires that, but because pubd does.  pubd probably should
      # be fixed to support a single client allowed to update multiple
      # trees, but for the moment the easiest way forward is just to
      # enforce a 1:1 mapping between <parent/> and <repository/> objects

      for repository in tree.getiterator("repository"):

        repository_handle = repository.get("handle")
        repository_pdu = repository_pdus.pop(repository_handle, None)
        repository_uri = repository.get("service_uri")
        repository_cert = findbase64(repository, "bpki_certificate")

        if (repository_pdu is None or
            repository_pdu.bsc_handle != bsc_handle or
            repository_pdu.peer_contact_uri != repository_uri or
            repository_pdu.bpki_cert != repository_cert):
          rpkid_query.append(rpki.left_right.repository_elt.make_pdu(
            action = "create" if repository_pdu is None else "set",
            tag = repository_handle,
            self_handle = handle,
            repository_handle = repository_handle,
            bsc_handle = bsc_handle,
            peer_contact_uri = repository_uri,
            bpki_cert = repository_cert))

      rpkid_query.extend(rpki.left_right.repository_elt.make_pdu(
        action = "destroy", self_handle = handle, repository_handle = r) for r in repository_pdus)

      # <parent/> setup code currently assumes 1:1 mapping between
      # <repository/> and <parent/>, and further assumes that the handles
      # for an associated pair are the identical (that is:
      # parent.repository_handle == parent.parent_handle).

      for parent in tree.getiterator("parent"):

        parent_handle = parent.get("handle")
        parent_pdu = parent_pdus.pop(parent_handle, None)
        parent_uri = parent.get("service_uri")
        parent_myhandle = parent.get("myhandle")
        parent_sia_base = parent.get("sia_base")
        parent_cms_cert = findbase64(parent, "bpki_cms_certificate")
        parent_https_cert = findbase64(parent, "bpki_https_certificate")

        if (parent_pdu is None or
            parent_pdu.bsc_handle != bsc_handle or
            parent_pdu.repository_handle != parent_handle or
            parent_pdu.peer_contact_uri != parent_uri or
            parent_pdu.sia_base != parent_sia_base or
            parent_pdu.sender_name != parent_myhandle or
            parent_pdu.recipient_name != parent_handle or
            parent_pdu.bpki_cms_cert != parent_cms_cert or
            parent_pdu.bpki_https_cert != parent_https_cert):
          rpkid_query.append(rpki.left_right.parent_elt.make_pdu(
            action = "create" if parent_pdu is None else "set",
            tag = parent_handle,
            self_handle = handle,
            parent_handle = parent_handle,
            bsc_handle = bsc_handle,
            repository_handle = parent_handle,
            peer_contact_uri = parent_uri,
            sia_base = parent_sia_base,
            sender_name = parent_myhandle,
            recipient_name = parent_handle,
            bpki_cms_cert = parent_cms_cert,
            bpki_https_cert = parent_https_cert))

      rpkid_query.extend(rpki.left_right.parent_elt.make_pdu(
        action = "destroy", self_handle = handle, parent_handle = p) for p in parent_pdus)

      # Children are simpler than parents, because they call us, so no URL
      # to construct and figuring out what certificate to use is their
      # problem, not ours.

      for child in tree.getiterator("child"):

        child_handle = child.get("handle")
        child_pdu = child_pdus.pop(child_handle, None)
        child_cert = findbase64(child, "bpki_certificate")

        if (child_pdu is None or
            child_pdu.bsc_handle != bsc_handle or
            child_pdu.bpki_cert != child_cert):
          rpkid_query.append(rpki.left_right.child_elt.make_pdu(
            action = "create" if child_pdu is None else "set",
            tag = child_handle,
            self_handle = handle,
            child_handle = child_handle,
            bsc_handle = bsc_handle,
            bpki_cert = child_cert))

      rpkid_query.extend(rpki.left_right.child_elt.make_pdu(
        action = "destroy", self_handle = handle, child_handle = c) for c in child_pdus)

      # Publication setup.

      if self.run_pubd:

        for f in self.entitydb.iterate("pubclients", "*.xml"):
          c = etree_read(f)

          client_handle = c.get("client_handle")
          client_base_uri = c.get("sia_base")
          client_bpki_cert = rpki.x509.X509(PEM_file = self.bpki_servers.fxcert(c.findtext("bpki_client_ta")))
          client_pdu = client_pdus.pop(client_handle, None)

          if (client_pdu is None or
              client_pdu.base_uri != client_base_uri or
              client_pdu.bpki_cert != client_bpki_cert):
            pubd_query.append(rpki.publication.client_elt.make_pdu(
              action = "create" if client_pdu is None else "set",
              client_handle = client_handle,
              bpki_cert = client_bpki_cert,
              base_uri = client_base_uri))

        pubd_query.extend(rpki.publication.client_elt.make_pdu(
            action = "destroy", client_handle = p) for p in client_pdus)

      # If we changed anything, ship updates off to daemons

      if rpkid_query:
        rpkid_reply = call_rpkid(*rpkid_query)
        bsc_pdus = dict((x.bsc_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.bsc_elt))
        if bsc_handle in bsc_pdus and bsc_pdus[bsc_handle].pkcs10_request:
          bsc_req = bsc_pdus[bsc_handle].pkcs10_request
        for r in rpkid_reply:
          assert not isinstance(r, rpki.left_right.report_error_elt)

      if pubd_query:
        assert self.run_pubd
        pubd_reply = call_pubd(*pubd_query)
        for r in pubd_reply:
          assert not isinstance(r, rpki.publication.report_error_elt)

      # Rewrite XML.

      e = tree.find("bpki_bsc_pkcs10")
      if e is None and bsc_req is not None:
        e = SubElement(tree, "bpki_bsc_pkcs10")
      elif bsc_req is None:
        tree.remove(e)

      if bsc_req is not None:
        assert e is not None
        s = bsc_req.get_Base64()
        s = "\n".join(s[64*i : 64*(i+1)] for i in xrange(1 + len(s)/64)).strip()
        e.text = "\n" + s + "\n"

      # Something weird going on here with lxml linked against recent
      # versions of libxml2.  Looks like modifying the tree above somehow
      # produces validation errors, but it works fine if we convert it to
      # a string and parse it again.  I'm not seeing any problems with any
      # of the other code that uses lxml to do validation, just this one
      # place.  Weird.  Kludge around it for now.
      #
      #tree = lxml.etree.fromstring(lxml.etree.tostring(tree))

      etree_write(tree, xmlfile, validate = True)

    db.close()


  def do_myirbe(self, arg):
    self.myirbe_main(arg.split())



if __name__ == "__main__":
  main()
