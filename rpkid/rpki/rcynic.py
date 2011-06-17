"""
Prototype of an iterator class to parse the output of an rcynic run.
This script will almost certainly move to the library package once
it's stable.

$Id$

Copyright (C) 2010-2011  Internet Systems Consortium ("ISC")

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

import sys, os, rpki.x509, rpki.exceptions
from xml.etree.ElementTree import ElementTree

class UnknownObject(rpki.exceptions.RPKI_Exception):
  """
  Unrecognized object in rcynic result cache.
  """

class NotRsyncURI(rpki.exceptions.RPKI_Exception):
  """
  URI is not an rsync URI.
  """

class rcynic_object(object):
  """
  An object read from rcynic cache.
  """

  def __init__(self, filename, **kwargs):
    self.filename = filename
    for k, v in kwargs.iteritems():
      setattr(self, k, v)
    self.obj = self.obj_class(DER_file = filename)

  def __repr__(self):
    return "<%s %s %s at 0x%x>" % (self.__class__.__name__, self.uri, self.resources, id(self))

  def show_attrs(self, *attrs):
    """
    Print a bunch of object attributes, quietly ignoring any that
    might be missing.
    """
    for a in attrs:
      try:
        print "%s: %s" % (a.capitalize(), getattr(self, a))
      except AttributeError:
        pass

  def show(self):
    """
    Print common object attributes.
    """
    self.show_attrs("filename", "uri", "status", "timestamp")

class rcynic_certificate(rcynic_object):
  """
  A certificate from rcynic cache.
  """

  obj_class = rpki.x509.X509

  def __init__(self, filename, **kwargs):
    rcynic_object.__init__(self, filename, **kwargs)
    self.notBefore = self.obj.getNotBefore()
    self.notAfter =  self.obj.getNotAfter()
    self.aia_uri = self.obj.get_aia_uri()
    self.sia_directory_uri = self.obj.get_sia_directory_uri()
    self.manifest_uri = self.obj.get_sia_manifest_uri()
    self.resources = self.obj.get_3779resources()
    self.is_ca = self.obj.is_CA()
    self.serial = self.obj.getSerial()
    self.issuer = self.obj.getIssuer()
    self.subject = self.obj.getSubject()
    self.ski = self.obj.hSKI()
    self.aki = self.obj.hAKI()

  def show(self):
    """
    Print certificate attributes.
    """
    rcynic_object.show(self)
    self.show_attrs("notBefore", "notAfter", "aia_uri", "sia_directory_uri", "resources")

class rcynic_roa(rcynic_object):
  """
  A ROA from rcynic cache.
  """

  obj_class = rpki.x509.ROA

  _afi_map = dict((cls.resource_set_type.afi, cls)
                  for cls in (rpki.resource_set.roa_prefix_set_ipv4,
                              rpki.resource_set.roa_prefix_set_ipv6))

  def __init__(self, filename, **kwargs):
    rcynic_object.__init__(self, filename, **kwargs)
    self.obj.extract()
    self.asID = self.obj.get_content().asID.get()
    self.prefix_sets = []
    for fam in self.obj.get_content().ipAddrBlocks:
      prefix_set = self._afi_map[fam.addressFamily.get()]()
      addr_type = prefix_set.resource_set_type.range_type.datum_type
      self.prefix_sets.append(prefix_set)
      for addr in fam.addresses:
        prefix = addr.address.get()
        prefixlen = len(prefix)
        prefix = addr_type(rpki.resource_set._bs2long(prefix, addr_type.bits, 0))
        maxprefixlen = addr.maxLength.get()
        prefix_set.append(prefix_set.prefix_type(prefix, prefixlen, maxprefixlen))
    self.ee = rpki.x509.X509(POW = self.obj.get_POW().certs()[0])
    self.notBefore = self.ee.getNotBefore()
    self.notAfter = self.ee.getNotAfter()
    self.aia_uri = self.ee.get_aia_uri()
    self.resources = self.ee.get_3779resources()
    self.issuer = self.ee.getIssuer()
    self.serial = self.ee.getSerial()
    self.subject = self.ee.getSubject()
    self.aki = self.ee.hAKI()
    self.ski = self.ee.hSKI()

  def show(self):
    """
    Print ROA attributes.
    """
    rcynic_object.show(self)
    self.show_attrs("notBefore", "notAfter", "aia_uri", "resources", "asID")
    if self.prefix_sets:
      print "Prefixes:", ",".join(str(i) for i in self.prefix_sets)

class rcynic_ghostbuster(rcynic_object):
  """
  Ghostbuster record from the rcynic cache.
  """

  obj_class = rpki.x509.Ghostbuster

  def __init__(self, *args, **kwargs):
    rcynic_object.__init__(self, *args, **kwargs)
    self.obj.extract()
    self.vcard = self.obj.get_content()
    self.ee = rpki.x509.X509(POW = self.obj.get_POW().certs()[0])
    self.notBefore = self.ee.getNotBefore()
    self.notAfter = self.ee.getNotAfter()
    self.aia_uri = self.ee.get_aia_uri()
    self.issuer = self.ee.getIssuer()
    self.serial = self.ee.getSerial()
    self.subject = self.ee.getSubject()
    self.aki = self.ee.hAKI()
    self.ski = self.ee.hSKI()

  def show(self):
    rcynic_object.show(self)
    self.show_attrs("notBefore", "notAfter", "vcard")

file_name_classes = {
  ".cer" : rcynic_certificate,
  ".gbr" : rcynic_ghostbuster,
  ".roa" : rcynic_roa }

class rcynic_file_iterator(object):
  """
  Iterate over files in an rcynic output tree, yielding a Python
  representation of each object found.
  """

  def __init__(self, rcynic_root,
               authenticated_subdir = "authenticated"):
    self.rcynic_dir = os.path.join(rcynic_root, authenticated_subdir)

  def __iter__(self):
    for root, dirs, files in os.walk(self.rcynic_dir):
      for filename in files:
        filename = os.path.join(root, filename)
        ext = os.path.splitext(filename)[1]
        if ext in file_name_classes:
          yield file_name_classes[ext](filename)

class rcynic_xml_iterator(object):
  """
  Iterate over validation_status entries in the XML output from an
  rcynic run.  Yields a tuple for each entry:

    URI, OK, status, timestamp, object

  where URI, status, and timestamp are the corresponding values from
  the XML element, OK is a boolean indicating whether validation was
  considered succesful, and object is a Python representation of the
  object in question.  If OK is True, object will be from rcynic's
  authenticated output tree; otherwise, object will be from rcynic's
  unauthenticated output tree.

  Note that it is possible for the same URI to appear in more than one
  validation_status element; in such cases, the succesful case (OK
  True) should be the last entry (as rcynic will stop trying once it
  gets a good copy), but there may be multiple failures, which might
  or might not have different status codes.
  """

  def __init__(self, rcynic_root, xml_file,
               authenticated_subdir = "authenticated",
               authenticated_old_subdir = "authenticated.old",
               unauthenticated_subdir = "unauthenticated"):
    self.rcynic_root = rcynic_root
    self.xml_file = xml_file
    self.authenticated_subdir = os.path.join(rcynic_root, authenticated_subdir)
    self.authenticated_old_subdir = os.path.join(rcynic_root, authenticated_old_subdir)
    self.unauthenticated_subdir = os.path.join(rcynic_root, unauthenticated_subdir)

  base_uri = "rsync://"

  def uri_to_filename(self, uri):
    if uri.startswith(self.base_uri):
      return uri[len(self.base_uri):]
    else:
      raise NotRsyncURI, "Not an rsync URI %r" % uri

  def __iter__(self):

    for validation_status in ElementTree(file = self.xml_file).getroot().getiterator("validation_status"):
      timestamp = validation_status.get("timestamp")
      status = validation_status.get("status")
      uri = validation_status.text.strip()
      ok = status == "validation_ok"
      filename = os.path.join(self.authenticated_subdir if ok else self.unauthenticated_subdir, self.uri_to_filename(uri))
      ext = os.path.splitext(filename)[1]
      if ext in file_name_classes:
        yield file_name_classes[ext](filename = filename, uri = uri, ok = ok, status = status, timestamp = timestamp)

def label_iterator(xml_file):
    """
    Returns an iterator which contains all defined labels from an rcynic XML
    output file.  Each item is a tuple of the form
    (label, kind, description).
    """

    for label in ElementTree(file=xml_file).find("labels"):
        yield label.tag, label.get("kind"), label.text.strip()


if __name__ == "__main__":
  rcynic_dir = os.path.normpath(os.path.join(sys.path[0], "..", "rcynic"))
  if False:
    try:
      for i in rcynic_file_iterator(os.path.join(rcynic_dir, "rcynic-data")):
        print i
    except IOError:
      pass
  if True:
    try:
      for i in rcynic_xml_iterator(os.path.join(rcynic_dir, "rcynic-data"),
                                   os.path.join(rcynic_dir, "rcynic.xml")):
        #print i
        i.show()
        print
    except IOError:
      pass
