"""
One X.509 implementation to rule them all...

...and in the darkness hide the twisty maze of partially overlapping
X.509 support packages in Python.

There are several existing packages, none of which do quite what I
need, due to age, lack of documentation, specialization, or lack of
foresight on somebody's part (perhaps mine).  This module attempts to
bring together the functionality I need in a way that hides at least
some of the nasty details.  This involves a lot of format conversion.

$Id$


Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")

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

import rpki.POW
import base64
import lxml.etree
import os
import subprocess
import email.mime.application
import email.utils
import mailbox
import time
import rpki.exceptions
import rpki.resource_set
import rpki.oids
import rpki.sundial
import rpki.log
import rpki.async
import rpki.relaxng

def base64_with_linebreaks(der):
  """
  Encode DER (really, anything) as Base64 text, with linebreaks to
  keep the result (sort of) readable.
  """
  b = base64.b64encode(der)
  n = len(b)
  return "\n" + "\n".join(b[i : min(i + 64, n)] for i in xrange(0, n, 64)) + "\n"

class PEM_converter(object):
  """
  Convert between DER and PEM encodings for various kinds of ASN.1 data.
  """

  def __init__(self, kind):    # "CERTIFICATE", "RSA PRIVATE KEY", ...
    """
    Initialize PEM_converter.
    """
    self.b = "-----BEGIN %s-----" % kind
    self.e = "-----END %s-----"   % kind

  def looks_like_PEM(self, text):
    """
    Guess whether text looks like a PEM encoding.
    """
    b = text.find(self.b)
    return b >= 0 and text.find(self.e) > b + len(self.b)

  def to_DER(self, pem):
    """
    Convert from PEM to DER.
    """
    lines = [line.strip() for line in pem.splitlines(0)]
    while lines and lines.pop(0) != self.b:
      pass
    while lines and lines.pop(-1) != self.e:
      pass
    if not lines:
      raise rpki.exceptions.EmptyPEM, "Could not find PEM in:\n%s" % pem
    return base64.b64decode("".join(lines))

  def to_PEM(self, der):
    """
    Convert from DER to PEM.
    """
    return self.b + base64_with_linebreaks(der) + self.e + "\n"

def first_rsync_uri(xia):
  """
  Find first rsync URI in a sequence of AIA or SIA URIs.
  Returns the URI if found, otherwise None.
  """

  if xia is not None:
    for uri in xia:
      if uri.startswith("rsync://"):
        return uri
  return None

def _find_xia_uri(extension, name):
  """
  Find a rsync URI in an SIA or AIA extension.
  Returns the URI if found, otherwise None.
  """
  oid = rpki.oids.name2oid[name]

  # extension may be None if the AIA is not present
  if extension:
    for method, location in extension:
      if method == oid and location[0] == "uri" and location[1].startswith("rsync://"):
        return location[1]
  return None

class X501DN(object):
  """
  Class to hold an X.501 Distinguished Name.

  This is nothing like a complete implementation, just enough for our
  purposes.  See RFC 5280 4.1.2.4 for the ASN.1 details.  In brief:

    - A DN is a SEQUENCE OF RDNs.

    - A RDN is a SET OF AttributeAndValues; in practice, multi-value
      RDNs are rare, so an RDN is almost always a set with a single
      element.

    - An AttributeAndValue is a SEQUENCE consisting of a OID and a
      value, where a whole bunch of things including both syntax and
      semantics of the value are determined by the OID.

    - The value is some kind of ASN.1 string; there are far too many
      encoding options options, most of which are either strongly
      discouraged or outright forbidden by the PKIX profile, but which
      persist for historical reasons.  The only ones PKIX actually
      likes are PrintableString and UTF8String, but there are nuances
      and special cases where some of the others are required.

  The RPKI profile further restricts DNs to a single mandatory
  CommonName attribute with a single optional SerialNumber attribute
  (not to be confused with the certificate serial number).

  BPKI certificates should (we hope) follow the general PKIX guideline
  but the ones we construct ourselves are likely to be relatively
  simple.
  """

  def __str__(self):
    return "".join("/" + "+".join("%s=%s" % (rpki.oids.safe_dotted2name(a[0]), a[1])
                                  for a in rdn)
                   for rdn in self.dn)

  def __cmp__(self, other):
    return cmp(self.dn, other.dn)

  def __repr__(self):
    return rpki.log.log_repr(self, str(self))

  def _debug(self):
    if False:
      import traceback
      for chunk in traceback.format_stack(limit = 5):
        for line in chunk.splitlines():
          rpki.log.debug("== %s" % line)
    rpki.log.debug("++ %r %r" % (self, self.dn))
      
  @classmethod
  def from_cn(cls, s):
    assert isinstance(s, (str, unicode))
    self = cls()
    self.dn = (((rpki.oids.safe_name2dotted("commonName"), s),),)
    return self

  @classmethod
  def from_POW(cls, t):
    assert isinstance(t, tuple)
    self = cls()
    self.dn = t
    return self

  def get_POW(self):
    return self.dn

class DER_object(object):
  """
  Virtual class to hold a generic DER object.
  """

  ## Formats supported in this object
  formats = ("DER",)

  ## PEM converter for this object
  pem_converter = None

  ## Other attributes that self.clear() should whack
  other_clear = ()

  ## @var DER
  ## DER value of this object

  def empty(self):
    """
    Test whether this object is empty.
    """
    return all(getattr(self, a, None) is None for a in self.formats)

  def clear(self):
    """
    Make this object empty.
    """
    for a in self.formats + self.other_clear:
      setattr(self, a, None)
    self.filename = None
    self.timestamp = None

  def __init__(self, **kw):
    """
    Initialize a DER_object.
    """
    self.clear()
    if len(kw):
      self.set(**kw)

  def set(self, **kw):
    """
    Set this object by setting one of its known formats.

    This method only allows one to set one format at a time.
    Subsequent calls will clear the object first.  The point of all
    this is to let the object's internal converters handle mustering
    the object into whatever format you need at the moment.
    """

    if len(kw) == 1:
      name = kw.keys()[0]
      if name in self.formats:
        self.clear()
        setattr(self, name, kw[name])
        return
      if name == "PEM":
        self.clear()
        self.DER = self.pem_converter.to_DER(kw[name])
        return
      if name == "Base64":
        self.clear()
        self.DER = base64.b64decode(kw[name])
        return
      if name == "Auto_update":
        self.filename = kw[name]
        self.check_auto_update()
        return
      if name in ("PEM_file", "DER_file", "Auto_file"):
        f = open(kw[name], "rb")
        value = f.read()
        f.close()
        if name == "PEM_file" or (name == "Auto_file" and self.pem_converter.looks_like_PEM(value)):
          value = self.pem_converter.to_DER(value)
        self.clear()
        self.DER = value
        return
    raise rpki.exceptions.DERObjectConversionError, "Can't honor conversion request %r" % (kw,)
  
  def check_auto_update(self):
    """
    Check for updates to a DER object that auto-updates from a file.
    """
    if self.filename is None:
      return
    filename = self.filename
    timestamp = os.stat(self.filename).st_mtime
    if self.timestamp is None or self.timestamp < timestamp:
      rpki.log.debug("Updating %s, timestamp %s" % (filename, rpki.sundial.datetime.fromtimestamp(timestamp)))
      f = open(filename, "rb")
      value = f.read()
      f.close()
      if self.pem_converter.looks_like_PEM(value):
        value = self.pem_converter.to_DER(value)
      self.clear()
      self.DER = value
      self.filename = filename
      self.timestamp = timestamp

  def check(self):
    """
    Perform basic checks on a DER object.
    """
    assert not self.empty()
    self.check_auto_update()

  def get_DER(self):
    """
    Get the DER value of this object.

    Subclasses will almost certainly override this method.
    """
    self.check()
    if self.DER:
      return self.DER
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_Base64(self):
    """
    Get the Base64 encoding of the DER value of this object.
    """
    return base64_with_linebreaks(self.get_DER())

  def get_PEM(self):
    """
    Get the PEM representation of this object.
    """
    return self.pem_converter.to_PEM(self.get_DER())

  def __cmp__(self, other):
    """
    Compare two DER-encoded objects.
    """
    if self is None and other is None:
      return 0
    elif self is None:
      return -1
    elif other is None:
      return 1
    elif isinstance(other, str):
      return cmp(self.get_DER(), other)
    else:
      return cmp(self.get_DER(), other.get_DER())

  def hSKI(self):
    """
    Return hexadecimal string representation of SKI for this object.
    Only work for subclasses that implement get_SKI().
    """
    ski = self.get_SKI()
    return ":".join(("%02X" % ord(i) for i in ski)) if ski else ""

  def gSKI(self):
    """
    Calculate g(SKI) for this object.  Only work for subclasses
    that implement get_SKI().
    """
    return base64.urlsafe_b64encode(self.get_SKI()).rstrip("=")

  def hAKI(self):
    """
    Return hexadecimal string representation of AKI for this
    object.  Only work for subclasses that implement get_AKI().
    """
    aki = self.get_AKI()
    return ":".join(("%02X" % ord(i) for i in aki)) if aki else ""

  def gAKI(self):
    """
    Calculate g(AKI) for this object.  Only work for subclasses
    that implement get_AKI().
    """
    return base64.urlsafe_b64encode(self.get_AKI()).rstrip("=")

  def get_AKI(self):
    """
    Get the AKI extension from this object.  Only works for subclasses
    that support getExtension().
    """
    return self.get_POW().getAKI()

  def get_SKI(self):
    """
    Get the SKI extension from this object.  Only works for subclasses
    that support getExtension().
    """
    return self.get_POW().getSKI()

  def get_SIA(self):
    """
    Get the SIA extension from this object.  Only works for subclasses
    that support getSIA().
    """
    return self.get_POW().getSIA()

  def get_sia_directory_uri(self):
    """
    Get SIA directory (id-ad-caRepository) URI from this object.
    Only works for subclasses that support getSIA().
    """
    sia = self.get_POW().getSIA()
    return None if sia is None else first_rsync_uri(sia[0])

  def get_sia_manifest_uri(self):
    """
    Get SIA manifest (id-ad-rpkiManifest) URI from this object.
    Only works for subclasses that support getSIA().
    """
    sia = self.get_POW().getSIA()
    return None if sia is None else first_rsync_uri(sia[1])

  def get_sia_object_uri(self):
    """
    Get SIA object (id-ad-signedObject) URI from this object.
    Only works for subclasses that support getSIA().
    """
    sia = self.get_POW().getSIA()
    return None if sia is None else first_rsync_uri(sia[2])

  def get_AIA(self):
    """
    Get the SIA extension from this object.  Only works for subclasses
    that support getAIA().
    """
    return self.get_POW().getAIA()

  def get_aia_uri(self):
    """
    Get AIA (id-ad-caIssuers) URI from this object.
    Only works for subclasses that support getAIA().
    """
    return first_rsync_uri(self.get_POW().getAIA())

  def get_basicConstraints(self):
    """
    Get the basicConstraints extension from this object.  Only works
    for subclasses that support getExtension().
    """
    return self.get_POW().getBasicConstraints()

  def is_CA(self):
    """
    Return True if and only if object has the basicConstraints
    extension and its cA value is true.
    """
    basicConstraints = self.get_basicConstraints()
    return basicConstraints is not None and basicConstraints[0]

  def get_3779resources(self):
    """
    Get RFC 3779 resources as rpki.resource_set objects.
    """
    resources = rpki.resource_set.resource_bag.from_POW_rfc3779(self.get_POW().getRFC3779())
    try:
      resources.valid_until = self.getNotAfter()
    except AttributeError:
      pass
    return resources

  @classmethod
  def from_sql(cls, x):
    """
    Convert from SQL storage format.
    """
    return cls(DER = x)

  def to_sql(self):
    """
    Convert to SQL storage format.
    """
    return self.get_DER()

  def dumpasn1(self):
    """
    Pretty print an ASN.1 DER object using cryptlib dumpasn1 tool.
    Use a temporary file rather than popen4() because dumpasn1 uses
    seek() when decoding ASN.1 content nested in OCTET STRING values.
    """

    ret = None
    fn = "dumpasn1.%d.tmp" % os.getpid()
    try:
      f = open(fn, "wb")
      f.write(self.get_DER())
      f.close()
      p = subprocess.Popen(("dumpasn1", "-a", fn), stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
      ret = "\n".join(x for x in p.communicate()[0].splitlines() if x.startswith(" "))
    except Exception, e:
      ret = "[Could not run dumpasn1: %s]" % e
    finally:
      os.unlink(fn)
    return ret

  def tracking_data(self, uri):
    """
    Return a string containing data we want to log when tracking how
    objects move through the RPKI system.  Subclasses may wrap this to
    provide more information, but should make sure to include at least
    this information at the start of the tracking line.
    """
    try:
      d = rpki.POW.Digest(rpki.POW.SHA1_DIGEST)
      d.update(self.get_DER())
      return "%s %s %s" % (uri, self.creation_timestamp,
                           "".join(("%02X" % ord(b) for b in d.digest())))
    except:                             # pylint: disable=W0702
      return uri

class X509(DER_object):
  """
  X.509 certificates.

  This class is designed to hold all the different representations of
  X.509 certs we're using and convert between them.  X.509 support in
  Python a nasty maze of half-cooked stuff (except perhaps for
  cryptlib, which is just different).  Users of this module should not
  have to care about this implementation nightmare.
  """

  formats = ("DER", "POW")
  pem_converter = PEM_converter("CERTIFICATE")
  
  def get_DER(self):
    """
    Get the DER value of this certificate.
    """
    self.check()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWrite()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this certificate.
    """
    self.check()
    if not self.POW:                    # pylint: disable=E0203
      self.POW = rpki.POW.X509.derRead(self.get_DER())
    return self.POW

  def getIssuer(self):
    """
    Get the issuer of this certificate.
    """
    return X501DN.from_POW(self.get_POW().getIssuer())

  def getSubject(self):
    """
    Get the subject of this certificate.
    """
    return X501DN.from_POW(self.get_POW().getSubject())

  def getNotBefore(self):
    """
    Get the inception time of this certificate.
    """
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_POW().getNotBefore())

  def getNotAfter(self):
    """
    Get the expiration time of this certificate.
    """
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_POW().getNotAfter())

  def getSerial(self):
    """
    Get the serial number of this certificate.
    """
    return self.get_POW().getSerial()

  def getPublicKey(self):
    """
    Extract the public key from this certificate.
    """
    return RSApublic(POW = self.get_POW().getPublicKey())

  def get_SKI(self):
    """
    Get the SKI extension from this object.
    """
    return self.get_POW().getSKI()

  def expired(self):
    """
    Test whether this certificate has expired.
    """
    return self.getNotAfter() <= rpki.sundial.now()

  def issue(self, keypair, subject_key, serial, sia, aia, crldp, notAfter,
            cn = None, resources = None, is_ca = True):
    """
    Issue an RPKI certificate.
    """

    assert aia is not None and crldp is not None

    return self._issue(
      keypair     = keypair,
      subject_key = subject_key,
      serial      = serial,
      sia         = sia,
      aia         = aia,
      crldp       = crldp,
      notAfter    = notAfter,
      cn          = cn,
      resources   = resources,
      is_ca       = is_ca,
      aki         = self.get_SKI(),
      issuer_name = self.getSubject())


  @classmethod
  def self_certify(cls, keypair, subject_key, serial, sia, notAfter,
                   cn = None, resources = None):
    """
    Generate a self-certified RPKI certificate.
    """

    ski = subject_key.get_SKI()

    if cn is None:
      cn = "".join(("%02X" % ord(i) for i in ski))

    return cls._issue(
      keypair     = keypair,
      subject_key = subject_key,
      serial      = serial,
      sia         = sia,
      aia         = None,
      crldp       = None,
      notAfter    = notAfter,
      cn          = cn,
      resources   = resources,
      is_ca       = True,
      aki         = ski,
      issuer_name = X501DN.from_cn(cn))


  @classmethod
  def _issue(cls, keypair, subject_key, serial, sia, aia, crldp, notAfter,
             cn, resources, is_ca, aki, issuer_name):
    """
    Common code to issue an RPKI certificate.
    """

    now = rpki.sundial.now()
    ski = subject_key.get_SKI()

    if cn is None:
      cn = "".join(("%02X" % ord(i) for i in ski))

    cert = rpki.POW.X509()

    cert.setVersion(2)
    cert.setSerial(serial)
    cert.setIssuer(issuer_name.get_POW())
    cert.setSubject(X501DN.from_cn(cn).get_POW())
    cert.setNotBefore(now.toGeneralizedTime())
    cert.setNotAfter(notAfter.toGeneralizedTime())
    cert.setPublicKey(subject_key.get_POW())
    cert.setSKI(ski)
    cert.setAKI(aki)
    cert.setCertificatePolicies((POWify_OID("id-cp-ipAddr-asNumber"),))

    if crldp is not None:
      cert.setCRLDP((crldp,))

    if aia is not None:
      cert.setAIA((aia,))

    if is_ca:
      cert.setBasicConstraints(True, None)
      cert.setKeyUsage(frozenset(("keyCertSign", "cRLSign")))

    else:
      cert.setKeyUsage(frozenset(("digitalSignature",)))

    assert sia is not None or not is_ca

    if sia is not None:
      caRepository, rpkiManifest, signedObject = sia
      cert.setSIA(
        (caRepository,) if isinstance(caRepository, str) else caRepository,
        (rpkiManifest,) if isinstance(rpkiManifest, str) else rpkiManifest,
        (signedObject,) if isinstance(signedObject, str) else signedObject)

    if resources is not None:
      cert.setRFC3779(
        asn  = ((r.min, r.max) for r in resources.asn),
        ipv4 = ((rpki.POW.IPAddress(r.min, 4), rpki.POW.IPAddress(r.max, 4)) for r in resources.v4),
        ipv6 = ((rpki.POW.IPAddress(r.min, 6), rpki.POW.IPAddress(r.max, 6)) for r in resources.v6))

    cert.sign(keypair.get_POW(), rpki.POW.SHA256_DIGEST)

    return cls(POW = cert)

  def bpki_cross_certify(self, keypair, source_cert, serial, notAfter,
                         now = None, pathLenConstraint = 0):
    """
    Issue a BPKI certificate with values taking from an existing certificate.
    """
    return self.bpki_certify(
      keypair = keypair,
      subject_name = source_cert.getSubject(),
      subject_key = source_cert.getPublicKey(),
      serial = serial,
      notAfter = notAfter,
      now = now,
      pathLenConstraint = pathLenConstraint,
      is_ca = True)

  @classmethod
  def bpki_self_certify(cls, keypair, subject_name, serial, notAfter,
                        now = None, pathLenConstraint = None):
    """
    Issue a self-signed BPKI CA certificate.
    """
    return cls._bpki_certify(
      keypair = keypair,
      issuer_name = subject_name,
      subject_name = subject_name,
      subject_key = keypair.get_RSApublic(),
      serial = serial,
      now = now,
      notAfter = notAfter,
      pathLenConstraint = pathLenConstraint,
      is_ca = True)

  def bpki_certify(self, keypair, subject_name, subject_key, serial, notAfter, is_ca,
                   now = None, pathLenConstraint = None):
    """
    Issue a normal BPKI certificate.
    """
    assert keypair.get_RSApublic() == self.getPublicKey()
    return self._bpki_certify(
      keypair = keypair,
      issuer_name = self.getSubject(),
      subject_name = subject_name,
      subject_key = subject_key,
      serial = serial,
      now = now,
      notAfter = notAfter,
      pathLenConstraint = pathLenConstraint,
      is_ca = is_ca)

  @classmethod
  def _bpki_certify(cls, keypair, issuer_name, subject_name, subject_key,
                    serial, now, notAfter, pathLenConstraint, is_ca):
    """
    Issue a BPKI certificate.  This internal method does the real
    work, after one of the wrapper methods has extracted the relevant
    fields.
    """

    if now is None:
      now = rpki.sundial.now()

    issuer_key = keypair.get_RSApublic()

    assert (issuer_key == subject_key) == (issuer_name == subject_name)
    assert is_ca or issuer_name != subject_name
    assert is_ca or pathLenConstraint is None
    assert pathLenConstraint is None or (isinstance(pathLenConstraint, (int, long)) and
                                         pathLenConstraint >= 0)

    cert = rpki.POW.X509()
    cert.setVersion(2)
    cert.setSerial(serial)
    cert.setIssuer(issuer_name.get_POW())
    cert.setSubject(subject_name.get_POW())
    cert.setNotBefore(now.toGeneralizedTime())
    cert.setNotAfter(notAfter.toGeneralizedTime())
    cert.setPublicKey(subject_key.get_POW())
    cert.setSKI(subject_key.get_POW().calculateSKI())
    if issuer_key != subject_key:
      cert.setAKI(issuer_key.get_POW().calculateSKI())
    if is_ca:
      cert.setBasicConstraints(True, pathLenConstraint)
    cert.sign(keypair.get_POW(), rpki.POW.SHA256_DIGEST)
    return cls(POW = cert)

  @classmethod
  def normalize_chain(cls, chain):
    """
    Normalize a chain of certificates into a tuple of X509 objects.
    Given all the glue certificates needed for BPKI cross
    certification, it's easiest to allow sloppy arguments to the CMS
    validation methods and provide a single method that normalizes the
    allowed cases.  So this method allows X509, None, lists, and
    tuples, and returns a tuple of X509 objects.
    """
    if isinstance(chain, cls):
      chain = (chain,)
    return tuple(x for x in chain if x is not None)

  @property
  def creation_timestamp(self):
    """
    Time at which this object was created.
    """
    return self.getNotBefore()

class PKCS10(DER_object):
  """
  Class to hold a PKCS #10 request.
  """

  formats = ("DER", "POW")
  pem_converter = PEM_converter("CERTIFICATE REQUEST")

  ## @var expected_ca_keyUsage
  # KeyUsage extension flags expected for CA requests.

  expected_ca_keyUsage = frozenset(("keyCertSign", "cRLSign"))

  ## @var allowed_extensions
  # Extensions allowed by RPKI profile.

  allowed_extensions = frozenset(rpki.oids.safe_name2dotted(name)
                                 for name in ("basicConstraints",
                                              "keyUsage",
                                              "subjectInfoAccess"))

  def get_DER(self):
    """
    Get the DER value of this certification request.
    """
    self.check()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWrite()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this certification request.
    """
    self.check()
    if not self.POW:                    # pylint: disable=E0203
      self.POW = rpki.POW.PKCS10.derRead(self.get_DER())
    return self.POW

  def getSubject(self):
    """
    Extract the subject name from this certification request.
    """
    return X501DN.from_POW(self.get_POW().getSubject())

  def getPublicKey(self):
    """
    Extract the public key from this certification request.
    """
    return RSApublic(POW = self.get_POW().getPublicKey())

  def check_valid_rpki(self):
    """
    Check this certification request to see whether it's a valid
    request for an RPKI certificate.  This is broken out of the
    up-down protocol code because it's somewhat involved and the
    up-down code doesn't need to know the details.

    Throws an exception if the request isn't valid, so if this method
    returns at all, the request is ok.

    At the moment, this only allows requests for CA certificates; as a
    direct consequence, it also rejects ExtendedKeyUsage, because the
    RPKI profile only allows EKU for EE certificates.
    """

    if not self.get_POW().verify():
      raise rpki.exceptions.BadPKCS10, "Signature check failed"

    ver = self.get_POW().getVersion()

    if ver != 0:
      raise rpki.exceptions.BadPKCS10, "Bad version number %s" % ver

    alg = rpki.oids.safe_dotted2name(self.get_POW().getSignatureAlgorithm())

    if alg != "sha256WithRSAEncryption":
      raise rpki.exceptions.BadPKCS10, "Bad signature algorithm %s" % alg

    bc = self.get_POW().getBasicConstraints()
    
    if bc is None or not bc[0]:
      raise rpki.exceptions.BadPKCS10, "Request for EE certificate not allowed here"

    if bc[1] is not None:
      raise rpki.exceptions.BadPKCS10, "basicConstraints must not specify Path Length"

    ku = self.get_POW().getKeyUsage()

    if ku is not None and self.expected_ca_keyUsage != ku:
      raise rpki.exceptions.BadPKCS10, "keyUsage doesn't match basicConstraints: %r" % ku

    if any(oid not in self.allowed_extensions
           for oid in self.get_POW().getExtensionOIDs()):
      raise rpki.exceptions.BadExtension, "Forbidden extension(s) in certificate request"

    sias = self.get_POW().getSIA()

    if sias is None:
      raise rpki.exceptions.BadPKCS10, "Certificate request is missing SIA extension"

    caRepository, rpkiManifest, signedObject = sias

    if signedObject:
      raise rpki.exceptions.BadPKCS10, "CA certificate request has SIA id-ad-signedObject"

    if not caRepository:
      raise rpki.exceptions.BadPKCS10, "Certificate request is missing SIA id-ad-caRepository"

    if not any(uri.startswith("rsync://") for uri in caRepository):
      raise rpki.exceptions.BadPKCS10, "Certificate request SIA id-ad-caRepository contains no rsync URIs"

    if not rpkiManifest:
      raise rpki.exceptions.BadPKCS10, "Certificate request is missing SIA id-ad-rpkiManifest"
      
    if not any(uri.startswith("rsync://") for uri in rpkiManifest):
      raise rpki.exceptions.BadPKCS10, "Certificate request SIA id-ad-rpkiManifest contains no rsync URIs"

    if any(uri.startswith("rsync://") and not uri.endswith("/") for uri in caRepository):
      raise rpki.exceptions.BadPKCS10, "Certificate request SIA id-ad-caRepository does not end with slash"

    if any(uri.startswith("rsync://") and uri.endswith("/") for uri in rpkiManifest):
      raise rpki.exceptions.BadPKCS10, "Certificate request SIA id-ad-rpkiManifest ends with slash"

  @classmethod
  def create(cls, keypair, exts = None, is_ca = False,
             caRepository = None, rpkiManifest = None, signedObject = None):
    """
    Create a new request for a given keypair.
    """

    assert exts is None, "Old calling sequence to rpki.x509.PKCS10.create()"

    cn = "".join(("%02X" % ord(i) for i in keypair.get_SKI()))

    if isinstance(caRepository, str):
      caRepository = (caRepository,)

    if isinstance(rpkiManifest, str):
      rpkiManifest = (rpkiManifest,)

    if isinstance(signedObject, str):
      signedObject = (signedObject,)

    req = rpki.POW.PKCS10()
    req.setVersion(0)
    req.setSubject(X501DN.from_cn(cn).get_POW())
    req.setPublicKey(keypair.get_POW())

    if is_ca:
      req.setBasicConstraints(True, None)
      req.setKeyUsage(cls.expected_ca_keyUsage)

    if caRepository or rpkiManifest or signedObject:
      req.setSIA(caRepository, rpkiManifest, signedObject)

    req.sign(keypair.get_POW(), rpki.POW.SHA256_DIGEST)
    return cls(POW = req)

## @var generate_insecure_debug_only_rsa_key
# Debugging hack to let us save throwaway RSA keys from one debug
# session to the next.  DO NOT USE THIS IN PRODUCTION.

generate_insecure_debug_only_rsa_key = None

class insecure_debug_only_rsa_key_generator(object):

  def __init__(self, filename, keyno = 0):
    try:
      try:
        import gdbm as dbm_du_jour
      except ImportError:
        import dbm as dbm_du_jour
      self.keyno = long(keyno)
      self.filename = filename
      self.db = dbm_du_jour.open(filename, "c")
    except:
      rpki.log.warn("insecure_debug_only_rsa_key_generator initialization FAILED, hack inoperative")
      raise

  def __call__(self):
    k = str(self.keyno)
    try:
      v = rpki.POW.Asymmetric.derReadPrivate(self.db[k])
    except KeyError:
      v = rpki.POW.Asymmetric(rpki.POW.RSA_CIPHER, 2048)
      self.db[k] = v.derWritePrivate()
    self.keyno += 1
    return v

class RSA(DER_object):
  """
  Class to hold an RSA key pair.
  """

  formats = ("DER", "POW")
  pem_converter = PEM_converter("RSA PRIVATE KEY")
  
  def get_DER(self):
    """
    Get the DER value of this keypair.
    """
    self.check()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWritePrivate()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this keypair.
    """
    self.check()
    if not self.POW:                    # pylint: disable=E0203
      self.POW = rpki.POW.Asymmetric.derReadPrivate(self.get_DER())
    return self.POW

  @classmethod
  def generate(cls, keylength = 2048, quiet = False):
    """
    Generate a new keypair.
    """
    if not quiet:
      rpki.log.debug("Generating new %d-bit RSA key" % keylength)
    if generate_insecure_debug_only_rsa_key is not None:
      return cls(POW = generate_insecure_debug_only_rsa_key())
    else:
      return cls(POW = rpki.POW.Asymmetric(rpki.POW.RSA_CIPHER, keylength))

  def get_public_DER(self):
    """
    Get the DER encoding of the public key from this keypair.
    """
    return self.get_POW().derWritePublic()

  def get_SKI(self):
    """
    Calculate the SKI of this keypair.
    """
    return self.get_POW().calculateSKI()

  def get_RSApublic(self):
    """
    Convert the public key of this keypair into a RSApublic object.
    """
    return RSApublic(DER = self.get_public_DER())

class RSApublic(DER_object):
  """
  Class to hold an RSA public key.
  """

  formats = ("DER", "POW")
  pem_converter = PEM_converter("RSA PUBLIC KEY")
  
  def get_DER(self):
    """
    Get the DER value of this public key.
    """
    self.check()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWritePublic()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this public key.
    """
    self.check()
    if not self.POW:                    # pylint: disable=E0203
      self.POW = rpki.POW.Asymmetric.derReadPublic(self.get_DER())
    return self.POW

  def get_SKI(self):
    """
    Calculate the SKI of this public key.
    """
    return self.get_POW().calculateSKI()

def POWify_OID(oid):
  """
  Utility function to convert tuple form of an OID to the
  dotted-decimal string form that rpki.POW uses.
  """
  if isinstance(oid, str):
    return POWify_OID(rpki.oids.name2oid[oid])
  else:
    return ".".join(str(i) for i in oid)

class CMS_object(DER_object):
  """
  Abstract class to hold a CMS object.
  """

  formats = ("DER", "POW")
  econtent_oid = POWify_OID("id-data")
  pem_converter = PEM_converter("CMS")
  POW_class = rpki.POW.CMS

  ## @var dump_on_verify_failure
  # Set this to True to get dumpasn1 dumps of ASN.1 on CMS verify failures.

  dump_on_verify_failure = True

  ## @var debug_cms_certs
  # Set this to True to log a lot of chatter about CMS certificates.

  debug_cms_certs = False

  ## @var dump_using_dumpasn1
  # Set this to use external dumpasn1 program, which is prettier and
  # more informative than OpenSSL's CMS text dump, but which won't
  # work if the dumpasn1 program isn't installed.

  dump_using_dumpasn1 = False

  ## @var require_crls
  # Set this to False to make CMS CRLs optional in the cases where we
  # would otherwise require them.  Some day this option should go away
  # and CRLs should be uncondtionally mandatory in such cases.

  require_crls = False
  
  ## @var allow_extra_certs
  # Set this to True to allow CMS messages to contain CA certificates.

  allow_extra_certs = False
  
  ## @var allow_extra_crls
  # Set this to True to allow CMS messages to contain multiple CRLs.

  allow_extra_crls = False
  
  ## @var print_on_der_error
  # Set this to True to log alleged DER when we have trouble parsing
  # it, in case it's really a Perl backtrace or something.

  print_on_der_error = True

  def get_DER(self):
    """
    Get the DER value of this CMS_object.
    """
    self.check()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWrite()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this CMS_object.
    """
    self.check()
    if not self.POW:                    # pylint: disable=E0203
      self.POW = self.POW_class.derRead(self.get_DER())
    return self.POW

  def get_signingTime(self):
    """
    Extract signingTime from CMS signed attributes.
    """
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_POW().signingTime())

  def verify(self, ta):
    """
    Verify CMS wrapper and store inner content.
    """

    try:
      cms = self.get_POW()
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception:
      if self.print_on_der_error:
        rpki.log.debug("Problem parsing DER CMS message, might not really be DER: %r" %
                       self.get_DER())
      raise rpki.exceptions.UnparsableCMSDER

    if cms.eContentType() != self.econtent_oid:
      raise rpki.exceptions.WrongEContentType, "Got CMS eContentType %s, expected %s" % (
        cms.eContentType(), self.econtent_oid)

    certs = [X509(POW = x) for x in cms.certs()]
    crls  = [CRL(POW = c) for c in cms.crls()]

    if self.debug_cms_certs:
      for x in certs:
        rpki.log.debug("Received CMS cert issuer %s subject %s SKI %s" % (
          x.getIssuer(), x.getSubject(), x.hSKI()))
      for c in crls:
        rpki.log.debug("Received CMS CRL issuer %r" % (c.getIssuer(),))

    store = rpki.POW.X509Store()

    now = rpki.sundial.now()

    trusted_ee = None

    for x in X509.normalize_chain(ta):
      if self.debug_cms_certs:
        rpki.log.debug("CMS trusted cert issuer %s subject %s SKI %s" % (
          x.getIssuer(), x.getSubject(), x.hSKI()))
      if x.getNotAfter() < now:
        raise rpki.exceptions.TrustedCMSCertHasExpired("Trusted CMS certificate has expired",
                                                       "%s (%s)" % (x.getSubject(), x.hSKI()))
      if not x.is_CA():
        if trusted_ee is None:
          trusted_ee = x
        else:
          raise rpki.exceptions.MultipleCMSEECert("Multiple CMS EE certificates", *("%s (%s)" % (
            x.getSubject(), x.hSKI()) for x in ta if not x.is_CA()))
      store.addTrust(x.get_POW())

    if trusted_ee:
      if self.debug_cms_certs:
        rpki.log.debug("Trusted CMS EE cert issuer %s subject %s SKI %s" % (
          trusted_ee.getIssuer(), trusted_ee.getSubject(), trusted_ee.hSKI()))
      if len(certs) > 1 or (len(certs) == 1 and
                            (certs[0].getSubject() != trusted_ee.getSubject() or
                             certs[0].getPublicKey() != trusted_ee.getPublicKey())):
        raise rpki.exceptions.UnexpectedCMSCerts("Unexpected CMS certificates", *("%s (%s)" % (
          x.getSubject(), x.hSKI()) for x in certs))
      if crls:
        raise rpki.exceptions.UnexpectedCMSCRLs("Unexpected CRLs", *("%s (%s)" % (
          c.getIssuer(), c.hAKI()) for c in crls))

    else:
      untrusted_ee = [x for x in certs if not x.is_CA()]
      if len(untrusted_ee) < 1:
        raise rpki.exceptions.MissingCMSEEcert
      if len(untrusted_ee) > 1 or (not self.allow_extra_certs and len(certs) > len(untrusted_ee)):
        raise rpki.exceptions.UnexpectedCMSCerts("Unexpected CMS certificates", *("%s (%s)" % (
          x.getSubject(), x.hSKI()) for x in certs))
      if len(crls) < 1:
        if self.require_crls:
          raise rpki.exceptions.MissingCMSCRL
        else:
          rpki.log.warn("MISSING CMS CRL!  Ignoring per self.require_crls setting")
      if len(crls) > 1 and not self.allow_extra_crls:
        raise rpki.exceptions.UnexpectedCMSCRLs("Unexpected CRLs", *("%s (%s)" % (
          c.getIssuer(), c.hAKI()) for c in crls))

    for x in certs:
      if x.getNotAfter() < now:
        raise rpki.exceptions.CMSCertHasExpired("CMS certificate has expired", "%s (%s)" % (
          x.getSubject(), x.hSKI()))

    try:
      content = cms.verify(store)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception:
      if self.dump_on_verify_failure:
        if self.dump_using_dumpasn1:
          dbg = self.dumpasn1()
        else:
          dbg = cms.pprint()
        rpki.log.warn("CMS verification failed, dumping ASN.1 (%d octets):" % len(self.get_DER()))
        for line in dbg.splitlines():
          rpki.log.warn(line)
      raise rpki.exceptions.CMSVerificationFailed, "CMS verification failed"

    return content

  def extract(self):
    """
    Extract and store inner content from CMS wrapper without verifying
    the CMS.

    DANGER WILL ROBINSON!!!

    Do not use this method on unvalidated data.  Use the verify()
    method instead.

    If you don't understand this warning, don't use this method.
    """

    try:
      cms = self.get_POW()
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception:
      raise rpki.exceptions.UnparsableCMSDER

    if cms.eContentType() != self.econtent_oid:
      raise rpki.exceptions.WrongEContentType, "Got CMS eContentType %s, expected %s" % (
        cms.eContentType(), self.econtent_oid)

    return cms.verify(rpki.POW.X509Store(), None,
                      (rpki.POW.CMS_NOCRL | rpki.POW.CMS_NO_SIGNER_CERT_VERIFY |
                       rpki.POW.CMS_NO_ATTR_VERIFY | rpki.POW.CMS_NO_CONTENT_VERIFY))


  def sign(self, keypair, certs, crls = None, no_certs = False):
    """
    Sign and wrap inner content.
    """

    rpki.log.trace()

    if isinstance(certs, X509):
      cert = certs
      certs = ()
    else:
      cert = certs[0]
      certs = certs[1:]

    if crls is None:
      crls = ()
    elif isinstance(crls, CRL):
      crls = (crls,)

    if self.debug_cms_certs:
      rpki.log.debug("Signing with cert issuer %s subject %s SKI %s" % (
        cert.getIssuer(), cert.getSubject(), cert.hSKI()))
      for i, c in enumerate(certs):
        rpki.log.debug("Additional cert %d issuer %s subject %s SKI %s" % (
          i, c.getIssuer(), c.getSubject(), c.hSKI()))

    self._sign(cert.get_POW(),
               keypair.get_POW(),
               [x.get_POW() for x in certs],
               [c.get_POW() for c in crls],
               rpki.POW.CMS_NOCERTS if no_certs else 0)

  @property
  def creation_timestamp(self):
    """
    Time at which this object was created.
    """
    return self.get_signingTime()


class Wrapped_CMS_object(CMS_object):
  """
  Abstract class to hold CMS objects wrapping non-DER content (eg, XML
  or VCard).

  CMS-wrapped objects are a little different from the other DER_object
  types because the signed object is CMS wrapping some other kind of
  inner content.  A Wrapped_CMS_object is the outer CMS wrapped object
  so that the usual DER and PEM operations do the obvious things, and
  the inner content is handle via separate methods.
  """

  other_clear = ("content",)

  def get_content(self):
    """
    Get the inner content of this Wrapped_CMS_object.
    """
    if self.content is None:
      raise rpki.exceptions.CMSContentNotSet, "Inner content of CMS object %r is not set" % self
    return self.content

  def set_content(self, content):
    """
    Set the (inner) content of this Wrapped_CMS_object, clearing the wrapper.
    """
    self.clear()
    self.content = content

  def verify(self, ta):
    """
    Verify CMS wrapper and store inner content.
    """

    self.decode(CMS_object.verify(self, ta))
    return self.get_content()

  def extract(self):
    """
    Extract and store inner content from CMS wrapper without verifying
    the CMS.

    DANGER WILL ROBINSON!!!

    Do not use this method on unvalidated data.  Use the verify()
    method instead.

    If you don't understand this warning, don't use this method.
    """

    self.decode(CMS_object.extract(self))
    return self.get_content()

  def _sign(self, cert, keypair, certs, crls, flags):
    """
    Internal method to call POW to do CMS signature.  This is split
    out from the .sign() API method to handle differences in how
    different CMS-based POW classes handle the inner content.
    """

    cms = self.POW_class()
    cms.sign(cert, keypair, self.encode(), certs, crls, self.econtent_oid, flags)
    self.POW = cms
  

class DER_CMS_object(CMS_object):
  """
  Abstract class for CMS-based objects with DER-encoded content
  handled by C-level subclasses of rpki.POW.CMS.
  """

  def _sign(self, cert, keypair, certs, crls, flags):
    self.get_POW().sign(cert, keypair, certs, crls, self.econtent_oid, flags)


  def extract_if_needed(self):
    """
    Extract inner content if needed.  See caveats for .extract(), do
    not use unless you really know what you are doing.
    """

    try:
      self.get_POW().getVersion()
    except rpki.POW.NotVerifiedError:
      self.extract()


class SignedManifest(DER_CMS_object):
  """
  Class to hold a signed manifest.
  """

  pem_converter = PEM_converter("RPKI MANIFEST")
  econtent_oid = POWify_OID("id-ct-rpkiManifest")
  POW_class = rpki.POW.Manifest
  
  def getThisUpdate(self):
    """
    Get thisUpdate value from this manifest.
    """
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_POW().getThisUpdate())

  def getNextUpdate(self):
    """
    Get nextUpdate value from this manifest.
    """
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_POW().getNextUpdate())

  @classmethod
  def build(cls, serial, thisUpdate, nextUpdate, names_and_objs, keypair, certs, version = 0):
    """
    Build a signed manifest.
    """

    filelist = []
    for name, obj in names_and_objs:
      d = rpki.POW.Digest(rpki.POW.SHA256_DIGEST)
      d.update(obj.get_DER())
      filelist.append((name.rpartition("/")[2], d.digest()))
    filelist.sort(key = lambda x: x[0])

    obj = cls.POW_class()
    obj.setVersion(version)
    obj.setManifestNumber(serial)
    obj.setThisUpdate(thisUpdate.toGeneralizedTime())
    obj.setNextUpdate(nextUpdate.toGeneralizedTime())
    obj.setAlgorithm(POWify_OID(rpki.oids.name2oid["id-sha256"]))
    obj.addFiles(filelist)

    self = cls(POW = obj)
    self.sign(keypair, certs)
    return self

class ROA(DER_CMS_object):
  """
  Class to hold a signed ROA.
  """

  pem_converter = PEM_converter("ROUTE ORIGIN ATTESTATION")
  econtent_oid = POWify_OID("id-ct-routeOriginAttestation")
  POW_class = rpki.POW.ROA

  @classmethod
  def build(cls, asn, ipv4, ipv6, keypair, certs, version = 0):
    """
    Build a ROA.
    """
    ipv4 = ipv4.to_POW_roa_tuple() if ipv4 else None
    ipv6 = ipv6.to_POW_roa_tuple() if ipv6 else None
    obj = cls.POW_class()
    obj.setVersion(version)
    obj.setASID(asn)
    obj.setPrefixes(ipv4 = ipv4, ipv6 = ipv6)
    self = cls(POW = obj)
    self.sign(keypair, certs)
    return self

  def tracking_data(self, uri):
    """
    Return a string containing data we want to log when tracking how
    objects move through the RPKI system.
    """
    msg = DER_CMS_object.tracking_data(self, uri)
    try:
      try:
        self.get_POW().getVersion()
      except rpki.POW.NotVerifiedError:
        self.extract()
      asn = self.get_POW().getASID()
      text = []
      for prefixes in self.get_POW().getPrefixes():
        if prefixes is not None:
          for prefix, prefixlen, maxprefixlen in prefixes:
            if maxprefixlen is None or prefixlen == maxprefixlen:
              text.append("%s/%s" % (prefix, prefixlen))
            else:
              text.append("%s/%s-%s" % (prefix, prefixlen, maxprefixlen))
      text.sort()
      msg = "%s %s %s" % (msg, asn, ",".join(text))
    except:                             # pylint: disable=W0702
      pass
    return msg

class DeadDrop(object):
  """
  Dead-drop utility for storing copies of CMS messages for debugging or
  audit.  At the moment this uses Maildir mailbox format, as it has
  approximately the right properties and a number of useful tools for
  manipulating it already exist.
  """

  def __init__(self, name):
    self.name = name
    self.pid = os.getpid()
    self.maildir = mailbox.Maildir(name, factory = None, create = True)
    self.warned = False

  def dump(self, obj):
    try:
      now = time.time()
      msg = email.mime.application.MIMEApplication(obj.get_DER(), "x-rpki")
      msg["Date"] = email.utils.formatdate(now)
      msg["Subject"] = "Process %s dump of %r" % (self.pid, obj)
      msg["Message-ID"] = email.utils.make_msgid()
      msg["X-RPKI-PID"] = str(self.pid)
      msg["X-RPKI-Object"] = repr(obj)
      msg["X-RPKI-Timestamp"] = "%f" % now
      self.maildir.add(msg)
      self.warned = False
    except Exception, e:
      if not self.warned:
        rpki.log.warn("Could not write to mailbox %s: %e" % (self.name, e))
        self.warned = True

class XML_CMS_object(Wrapped_CMS_object):
  """
  Class to hold CMS-wrapped XML protocol data.
  """

  econtent_oid = POWify_OID("id-ct-xml")

  ## @var dump_outbound_cms
  # If set, we write all outbound XML-CMS PDUs to disk, for debugging.
  # If set, value should be a DeadDrop object.

  dump_outbound_cms = None

  ## @var dump_inbound_cms
  # If set, we write all inbound XML-CMS PDUs to disk, for debugging.
  # If set, value should be a DeadDrop object.

  dump_inbound_cms = None

  ## @var check_inbound_schema
  # If set, perform RelaxNG schema check on inbound messages.

  check_inbound_schema = True

  ## @var check_outbound_schema
  # If set, perform RelaxNG schema check on outbound messages.

  check_outbound_schema = False

  def encode(self):
    """
    Encode inner content for signing.
    """
    return lxml.etree.tostring(self.get_content(),
                               pretty_print = True,
                               encoding = self.encoding,
                               xml_declaration = True)

  def decode(self, xml):
    """
    Decode XML and set inner content.
    """
    self.content = lxml.etree.fromstring(xml)

  def pretty_print_content(self):
    """
    Pretty print XML content of this message.
    """
    return lxml.etree.tostring(self.get_content(),
                               pretty_print = True,
                               encoding = self.encoding,
                               xml_declaration = True)

  def schema_check(self):
    """
    Handle XML RelaxNG schema check.
    """
    try:
      self.schema.assertValid(self.get_content())
    except lxml.etree.DocumentInvalid:
      rpki.log.error("PDU failed schema check")
      for line in self.pretty_print_content().splitlines():
        rpki.log.warn(line)
      raise

  def dump_to_disk(self, prefix):
    """
    Write DER of current message to disk, for debugging.
    """
    f = open(prefix + rpki.sundial.now().isoformat() + "Z.cms", "wb")
    f.write(self.get_DER())
    f.close()

  def wrap(self, msg, keypair, certs, crls = None):
    """
    Wrap an XML PDU in CMS and return its DER encoding.
    """
    rpki.log.trace()
    if self.saxify is None:
      self.set_content(msg)
    else:
      self.set_content(msg.toXML())
    if self.check_outbound_schema:
      self.schema_check()
    self.sign(keypair, certs, crls)
    if self.dump_outbound_cms:
      self.dump_outbound_cms.dump(self)
    return self.get_DER()

  def unwrap(self, ta):
    """
    Unwrap a CMS-wrapped XML PDU and return Python objects.
    """
    if self.dump_inbound_cms:
      self.dump_inbound_cms.dump(self)
    self.verify(ta)
    if self.check_inbound_schema:
      self.schema_check()
    if self.saxify is None:
      return self.get_content()
    else:
      return self.saxify(self.get_content()) # pylint: disable=E1102

  def check_replay(self, timestamp):
    """
    Check CMS signing-time in this object against a recorded
    timestamp.  Raises an exception if the recorded timestamp is more
    recent, otherwise returns the new timestamp.
    """
    new_timestamp = self.get_signingTime()
    if timestamp is not None and timestamp > new_timestamp:
      raise rpki.exceptions.CMSReplay(
        "CMS replay: last message %s, this message %s" % (timestamp, new_timestamp))
    return new_timestamp

  def check_replay_sql(self, obj):
    """
    Like .check_replay() but gets recorded timestamp from
    "last_cms_timestamp" field of an SQL object and stores the new 
    timestamp back in that same field.
    """
    obj.last_cms_timestamp = self.check_replay(obj.last_cms_timestamp)
    obj.sql_mark_dirty()

  ## @var saxify
  # SAX handler hook.  Subclasses can set this to a SAX handler, in
  # which case .unwrap() will call it and return the result.
  # Otherwise, .unwrap() just returns a verified element tree.

  saxify = None

class SignedReferral(XML_CMS_object):
  encoding = "us-ascii"
  schema = rpki.relaxng.myrpki
  saxify = None

class Ghostbuster(Wrapped_CMS_object):
  """
  Class to hold Ghostbusters record (CMS-wrapped VCard).  This is
  quite minimal because we treat the VCard as an opaque byte string
  managed by the back-end.
  """

  pem_converter = PEM_converter("GHOSTBUSTERS RECORD")
  econtent_oid = POWify_OID("id-ct-rpkiGhostbusters")

  def encode(self):
    """
    Encode inner content for signing.  At the moment we're treating
    the VCard as an opaque byte string, so no encoding needed here.
    """
    return self.get_content()

  def decode(self, vcard):
    """
    Decode XML and set inner content.  At the moment we're treating
    the VCard as an opaque byte string, so no encoding needed here.
    """
    self.content = vcard

  @classmethod
  def build(cls, vcard, keypair, certs):
    """
    Build a Ghostbuster record.
    """
    self = cls()
    self.set_content(vcard)
    self.sign(keypair, certs)
    return self


class CRL(DER_object):
  """
  Class to hold a Certificate Revocation List.
  """

  formats = ("DER", "POW")
  pem_converter = PEM_converter("X509 CRL")
  
  def get_DER(self):
    """
    Get the DER value of this CRL.
    """
    self.check()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWrite()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this CRL.
    """
    self.check()
    if not self.POW:                    # pylint: disable=E0203
      self.POW = rpki.POW.CRL.derRead(self.get_DER())
    return self.POW

  def getThisUpdate(self):
    """
    Get thisUpdate value from this CRL.
    """
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_POW().getThisUpdate())

  def getNextUpdate(self):
    """
    Get nextUpdate value from this CRL.
    """
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_POW().getNextUpdate())

  def getIssuer(self):
    """
    Get issuer value of this CRL.
    """
    return X501DN.from_POW(self.get_POW().getIssuer())

  def getCRLNumber(self):
    """
    Get CRL Number value for this CRL.
    """
    return self.get_POW().getCRLNumber()

  @classmethod
  def generate(cls, keypair, issuer, serial, thisUpdate, nextUpdate, revokedCertificates, version = 1):
    """
    Generate a new CRL.
    """
    crl = rpki.POW.CRL()
    crl.setVersion(version)
    crl.setIssuer(issuer.getSubject().get_POW())
    crl.setThisUpdate(thisUpdate.toGeneralizedTime())
    crl.setNextUpdate(nextUpdate.toGeneralizedTime())
    crl.setAKI(issuer.get_SKI())
    crl.setCRLNumber(serial)
    crl.addRevocations((r[0], r[1].toGeneralizedTime())
                       for r in revokedCertificates)
    crl.sign(keypair.get_POW())
    return cls(POW = crl)

  @property
  def creation_timestamp(self):
    """
    Time at which this object was created.
    """
    return self.getThisUpdate()

## @var uri_dispatch_map
# Map of known URI filename extensions and corresponding classes.

uri_dispatch_map = {
  ".cer" : X509,
  ".crl" : CRL,
  ".gbr" : Ghostbuster,
  ".mft" : SignedManifest,
  ".mnf" : SignedManifest,
  ".roa" : ROA,
  }

def uri_dispatch(uri):
  """
  Return the Python class object corresponding to a given URI.
  """
  return uri_dispatch_map[os.path.splitext(uri)[1]]
