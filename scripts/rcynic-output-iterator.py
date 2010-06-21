"""
Prototype of an iterator class to parse the output of an rcynic run.
This script will almost certainly move to the library package once
it's stable.

$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

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

file_name_classes = {
  ".cer" : rpki.x509.X509,
  ".crl" : rpki.x509.CRL,
  ".roa" : rpki.x509.ROA,
  ".mnf" : rpki.x509.SignedManifest,
  ".mft" : rpki.x509.SignedManifest }

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
        try:
          file_name_class = file_name_classes[os.path.splitext(filename)[1]]
        except KeyError:
          raise UnknownObject, "Unknown object type %r" % filename
        else:
          yield file_name_class(DER_file = filename)

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
      try:
        file_name_class = file_name_classes[os.path.splitext(filename)[1]]
      except KeyError:
        raise UnknownObject, 'Unknown object type "%s"' % filename
      obj = file_name_class(DER_file = filename)
      if isinstance(obj, rpki.x509.CMS_object):
        obj.extract()
      yield uri, ok, status, timestamp, obj

if __name__ == "__main__":
  if False:
    for i in rcynic_file_iterator("/u/sra/rpki/subvert-rpki.hactrn.net/rcynic/rcynic-data"):
      print i
  if True:
    for i in rcynic_xml_iterator("/u/sra/rpki/subvert-rpki.hactrn.net/rcynic/rcynic-data", "/u/sra/rpki/subvert-rpki.hactrn.net/rcynic/rcynic.xml"):
      print i
