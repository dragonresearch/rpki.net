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


Copyright (C) 2009--2010  Internet Systems Consortium ("ISC")

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

import rpki.POW, rpki.POW.pkix, base64, lxml.etree, os, subprocess, sys
import email.mime.application, email.utils, mailbox, time
import rpki.exceptions, rpki.resource_set, rpki.oids, rpki.sundial
import rpki.manifest, rpki.roa, rpki.log, rpki.async

def base64_with_linebreaks(der):
  """
  Encode DER (really, anything) as Base64 text, with linebreaks to
  keep the result (sort of) readable.
  """
  b = base64.b64encode(der)
  n = len(b)
  return "\n" + "\n".join(b[i : min(i + 64, n)] for i in xrange(0, n, 64)) + "\n"

def calculate_SKI(public_key_der):
  """
  Calculate the SKI value given the DER representation of a public
  key, which requires first peeling the ASN.1 wrapper off the key.
  """
  k = rpki.POW.pkix.SubjectPublicKeyInfo()
  k.fromString(public_key_der)
  d = rpki.POW.Digest(rpki.POW.SHA1_DIGEST)
  d.update(k.subjectPublicKey.get())
  return d.digest()

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

def _find_xia_uri(extension, name):
  """
  Find a rsync URI in an SIA or AIA extension.
  Returns the URI if found, otherwise None.
  """
  oid = rpki.oids.name2oid[name]

  for method, location in extension:
    if method == oid and location[0] == "uri" and location[1].startswith("rsync://"):
      return location[1]
  return None

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
    aki = (self.get_POWpkix().getExtension(rpki.oids.name2oid["authorityKeyIdentifier"]) or ((), 0, None))[2]
    return aki[0] if isinstance(aki, tuple) else aki

  def get_SKI(self):
    """
    Get the SKI extension from this object.  Only works for subclasses
    that support getExtension().
    """
    return (self.get_POWpkix().getExtension(rpki.oids.name2oid["subjectKeyIdentifier"]) or ((), 0, None))[2]

  def get_SIA(self):
    """
    Get the SIA extension from this object.  Only works for subclasses
    that support getExtension().
    """
    return (self.get_POWpkix().getExtension(rpki.oids.name2oid["subjectInfoAccess"]) or ((), 0, None))[2]

  def get_sia_directory_uri(self):
    """
    Get SIA directory (id-ad-caRepository) URI from this object.
    Only works for subclasses that support getExtension().
    """
    return _find_xia_uri(self.get_SIA(), "id-ad-caRepository")

  def get_sia_manifest_uri(self):
    """
    Get SIA manifest (id-ad-rpkiManifest) URI from this object.
    Only works for subclasses that support getExtension().
    """
    return _find_xia_uri(self.get_SIA(), "id-ad-rpkiManifest")

  def get_AIA(self):
    """
    Get the SIA extension from this object.  Only works for subclasses
    that support getExtension().
    """
    return (self.get_POWpkix().getExtension(rpki.oids.name2oid["authorityInfoAccess"]) or ((), 0, None))[2]

  def get_aia_uri(self):
    """
    Get AIA (id-ad-caIssuers) URI from this object.
    Only works for subclasses that support getExtension().
    """
    return _find_xia_uri(self.get_AIA(), "id-ad-caIssuers")

  def get_basicConstraints(self):
    """
    Get the basicConstraints extension from this object.  Only works
    for subclasses that support getExtension().
    """
    return (self.get_POWpkix().getExtension(rpki.oids.name2oid["basicConstraints"]) or ((), 0, None))[2]

  def is_CA(self):
    """
    Return True if and only if object has the basicConstraints
    extension and its cA value is true.
    """
    basicConstraints = self.get_basicConstraints()
    return basicConstraints and basicConstraints[0] != 0

  def get_3779resources(self):
    """
    Get RFC 3779 resources as rpki.resource_set objects.  Only works
    for subclasses that support getExtensions().
    """
    resources = rpki.resource_set.resource_bag.from_rfc3779_tuples(self.get_POWpkix().getExtensions())
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
    finally:
      os.unlink(fn)
    return ret

class X509(DER_object):
  """
  X.509 certificates.

  This class is designed to hold all the different representations of
  X.509 certs we're using and convert between them.  X.509 support in
  Python a nasty maze of half-cooked stuff (except perhaps for
  cryptlib, which is just different).  Users of this module should not
  have to care about this implementation nightmare.
  """

  formats = ("DER", "POW", "POWpkix")
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
    if self.POWpkix:
      self.DER = self.POWpkix.toString()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this certificate.
    """
    self.check()
    if not self.POW:
      self.POW = rpki.POW.derRead(rpki.POW.X509_CERTIFICATE, self.get_DER())
    return self.POW

  def get_POWpkix(self):
    """
    Get the rpki.POW.pkix value of this certificate.
    """
    self.check()
    if not self.POWpkix:
      cert = rpki.POW.pkix.Certificate()
      cert.fromString(self.get_DER())
      self.POWpkix = cert
    return self.POWpkix

  def getIssuer(self):
    """
    Get the issuer of this certificate.
    """
    return self.get_POW().getIssuer()

  def getSubject(self):
    """
    Get the subject of this certificate.
    """
    return self.get_POW().getSubject()

  def getNotBefore(self):
    """
    Get the inception time of this certificate.
    """
    return rpki.sundial.datetime.fromASN1tuple(self.get_POWpkix().tbs.validity.notBefore.get())

  def getNotAfter(self):
    """
    Get the expiration time of this certificate.
    """
    return rpki.sundial.datetime.fromASN1tuple(self.get_POWpkix().tbs.validity.notAfter.get())

  def getSerial(self):
    """
    Get the serial number of this certificate.
    """
    return self.get_POW().getSerial()

  def getPublicKey(self):
    """
    Extract the public key from this certificate.
    """
    return RSApublic(DER = self.get_POWpkix().tbs.subjectPublicKeyInfo.toString())

  def expired(self):
    """
    Test whether this certificate has expired.
    """
    return self.getNotAfter() <= rpki.sundial.now()

  def issue(self, keypair, subject_key, serial, sia, aia, crldp, notAfter,
            cn = None, resources = None, is_ca = True):
    """
    Issue a certificate.
    """

    now = rpki.sundial.now()
    aki = self.get_SKI()
    ski = subject_key.get_SKI()

    if cn is None:
      cn = "".join(("%02X" % ord(i) for i in ski))

    # if notAfter is None: notAfter = now + rpki.sundial.timedelta(days = 30)

    cert = rpki.POW.pkix.Certificate()
    cert.setVersion(2)
    cert.setSerial(serial)
    cert.setIssuer(self.get_POWpkix().getSubject())
    cert.setSubject((((rpki.oids.name2oid["commonName"], ("printableString", cn)),),))
    cert.setNotBefore(now.toASN1tuple())
    cert.setNotAfter(notAfter.toASN1tuple())
    cert.tbs.subjectPublicKeyInfo.fromString(subject_key.get_DER())

    exts = [ ["subjectKeyIdentifier",   False, ski],
             ["authorityKeyIdentifier", False, (aki, (), None)],
             ["cRLDistributionPoints",  False, ((("fullName", (("uri", crldp),)), None, ()),)],
             ["authorityInfoAccess",    False, ((rpki.oids.name2oid["id-ad-caIssuers"], ("uri", aia)),)],
             ["certificatePolicies",    True,  ((rpki.oids.name2oid["id-cp-ipAddr-asNumber"], ()),)] ]

    if is_ca:
      exts.append(["basicConstraints",  True,  (1, None)])
      exts.append(["keyUsage",          True,  (0, 0, 0, 0, 0, 1, 1)])
    else:
      exts.append(["keyUsage",          True,  (1,)])

    if sia is not None:
      exts.append(["subjectInfoAccess", False, sia])
    else:
      assert not is_ca

    # This next bit suggests that perhaps .to_rfc3779_tuple() should
    # be raising an exception when there are no resources rather than
    # returning None.  Maybe refactor later.

    if resources is not None:
      r = resources.asn.to_rfc3779_tuple()
      if r is not None:
        exts.append(["sbgp-autonomousSysNum", True, (r, None)])
      r = [x for x in (resources.v4.to_rfc3779_tuple(), resources.v6.to_rfc3779_tuple()) if x is not None]
      if r:
        exts.append(["sbgp-ipAddrBlock", True, r])

    for x in exts:
      x[0] = rpki.oids.name2oid[x[0]]
    cert.setExtensions(exts)

    cert.sign(keypair.get_POW(), rpki.POW.SHA256_DIGEST)

    return X509(POWpkix = cert)

  def cross_certify(self, keypair, source_cert, serial, notAfter, now = None, pathLenConstraint = 0):
    """
    Issue a certificate with values taking from an existing certificate.
    This is used to construct some kinds oF BPKI certificates.
    """

    if now is None:
      now = rpki.sundial.now()

    assert isinstance(pathLenConstraint, int) and pathLenConstraint >= 0

    cert = rpki.POW.pkix.Certificate()
    cert.setVersion(2)
    cert.setSerial(serial)
    cert.setIssuer(self.get_POWpkix().getSubject())
    cert.setSubject(source_cert.get_POWpkix().getSubject())
    cert.setNotBefore(now.toASN1tuple())
    cert.setNotAfter(notAfter.toASN1tuple())
    cert.tbs.subjectPublicKeyInfo.set(
      source_cert.get_POWpkix().tbs.subjectPublicKeyInfo.get())
    cert.setExtensions((
      (rpki.oids.name2oid["subjectKeyIdentifier"  ], False, source_cert.get_SKI()),
      (rpki.oids.name2oid["authorityKeyIdentifier"], False, (self.get_SKI(), (), None)),
      (rpki.oids.name2oid["basicConstraints"      ], True,  (1, 0))))
    cert.sign(keypair.get_POW(), rpki.POW.SHA256_DIGEST)

    return X509(POWpkix = cert)

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

class PKCS10(DER_object):
  """
  Class to hold a PKCS #10 request.
  """

  formats = ("DER", "POWpkix")
  pem_converter = PEM_converter("CERTIFICATE REQUEST")
  
  def get_DER(self):
    """
    Get the DER value of this certification request.
    """
    self.check()
    if self.DER:
      return self.DER
    if self.POWpkix:
      self.DER = self.POWpkix.toString()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POWpkix(self):
    """
    Get the rpki.POW.pkix value of this certification request.
    """
    self.check()
    if not self.POWpkix:
      req = rpki.POW.pkix.CertificationRequest()
      req.fromString(self.get_DER())
      self.POWpkix = req
    return self.POWpkix

  def getPublicKey(self):
    """
    Extract the public key from this certification request.
    """
    return RSApublic(DER = self.get_POWpkix().certificationRequestInfo.subjectPublicKeyInfo.toString())

  def check_valid_rpki(self):
    """
    Check this certification request to see whether it's a valid
    request for an RPKI certificate.  This is broken out of the
    up-down protocol code because it's somewhat involved and the
    up-down code doesn't need to know the details.

    Throws an exception if the request isn't valid, so if this method
    returns at all, the request is ok.
    """

    if not self.get_POWpkix().verify():
      raise rpki.exceptions.BadPKCS10, "Signature check failed"

    if self.get_POWpkix().certificationRequestInfo.version.get() != 0:
      raise rpki.exceptions.BadPKCS10, \
            "Bad version number %s" % self.get_POWpkix().certificationRequestInfo.version

    if rpki.oids.oid2name.get(self.get_POWpkix().signatureAlgorithm.algorithm.get()) \
         not in ("sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption"):
      raise rpki.exceptions.BadPKCS10, "Bad signature algorithm %s" % self.get_POWpkix().signatureAlgorithm

    exts = self.get_POWpkix().getExtensions()
    for oid, critical, value in exts:
      if rpki.oids.oid2name.get(oid) not in ("basicConstraints", "keyUsage", "subjectInfoAccess"):
        raise rpki.exceptions.BadExtension, "Forbidden extension %s" % oid
    req_exts = dict((rpki.oids.oid2name[oid], value) for (oid, critical, value) in exts)

    if "basicConstraints" not in req_exts or not req_exts["basicConstraints"][0]:
      raise rpki.exceptions.BadPKCS10, "request for EE cert not allowed here"

    if req_exts["basicConstraints"][1] is not None:
      raise rpki.exceptions.BadPKCS10, "basicConstraints must not specify Path Length"

    if "keyUsage" in req_exts and (not req_exts["keyUsage"][5] or not req_exts["keyUsage"][6]):
      raise rpki.exceptions.BadPKCS10, "keyUsage doesn't match basicConstraints"

    for method, location in req_exts.get("subjectInfoAccess", ()):
      if rpki.oids.oid2name.get(method) == "id-ad-caRepository" and \
           (location[0] != "uri" or (location[1].startswith("rsync://") and not location[1].endswith("/"))):
        raise rpki.exceptions.BadPKCS10, "Certificate request includes bad SIA component: %r" % location

    # This one is an implementation restriction.  I don't yet
    # understand what the spec is telling me to do in this case.
    assert "subjectInfoAccess" in req_exts, "Can't (yet) handle PKCS #10 without an SIA extension"

  @classmethod
  def create_ca(cls, keypair, sia = None):
    """
    Create a new request for a given keypair, including given SIA value.
    """
    exts = [["basicConstraints", True, (1, None)],
            ["keyUsage",         True, (0, 0, 0, 0, 0, 1, 1)]]
    if sia is not None:
      exts.append(["subjectInfoAccess", False, sia])
    for x in exts:
      x[0] = rpki.oids.name2oid[x[0]]
    return cls.create(keypair, exts)

  @classmethod
  def create(cls, keypair, exts = None):
    """
    Create a new request for a given keypair, including given extensions.
    """
    cn = "".join(("%02X" % ord(i) for i in keypair.get_SKI()))
    req = rpki.POW.pkix.CertificationRequest()
    req.certificationRequestInfo.version.set(0)
    req.certificationRequestInfo.subject.set((((rpki.oids.name2oid["commonName"],
                                                ("printableString", cn)),),))
    if exts is not None:
      req.setExtensions(exts)
    req.sign(keypair.get_POW(), rpki.POW.SHA256_DIGEST)
    return cls(POWpkix = req)

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
      self.DER = self.POW.derWrite(rpki.POW.RSA_PRIVATE_KEY)
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this keypair.
    """
    self.check()
    if not self.POW:
      self.POW = rpki.POW.derRead(rpki.POW.RSA_PRIVATE_KEY, self.get_DER())
    return self.POW

  @classmethod
  def generate(cls, keylength = 2048):
    """
    Generate a new keypair.
    """
    rpki.log.debug("Generating new %d-bit RSA key" % keylength)
    return cls(POW = rpki.POW.Asymmetric(rpki.POW.RSA_CIPHER, keylength))

  def get_public_DER(self):
    """
    Get the DER encoding of the public key from this keypair.
    """
    return self.get_POW().derWrite(rpki.POW.RSA_PUBLIC_KEY)

  def get_SKI(self):
    """
    Calculate the SKI of this keypair.
    """
    return calculate_SKI(self.get_public_DER())

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
      self.DER = self.POW.derWrite(rpki.POW.RSA_PUBLIC_KEY)
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this public key.
    """
    self.check()
    if not self.POW:
      self.POW = rpki.POW.derRead(rpki.POW.RSA_PUBLIC_KEY, self.get_DER())
    return self.POW

  def get_SKI(self):
    """
    Calculate the SKI of this public key.
    """
    return calculate_SKI(self.get_DER())

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
  Class to hold a CMS-wrapped object.

  CMS-wrapped objects are a little different from the other DER_object
  types because the signed object is CMS wrapping inner content that's
  also ASN.1, and due to our current minimal support for CMS we can't
  just handle this as a pretty composite object.  So, for now anyway,
  a CMS_object is the outer CMS wrapped object so that the usual DER
  and PEM operations do the obvious things, and the inner content is
  handle via separate methods.
  """

  formats = ("DER", "POW")
  other_clear = ("content",)
  econtent_oid = POWify_OID("id-data")
  pem_converter = PEM_converter("CMS")

  ## @var dump_on_verify_failure
  # Set this to True to get dumpasn1 dumps of ASN.1 on CMS verify failures.

  dump_on_verify_failure = True

  ## @var debug_cms_certs
  # Set this to True to log a lot of chatter about CMS certificates.

  debug_cms_certs = False

  ## @var require_crls
  # Set this to False to make CMS CRLs optional in the cases where we
  # would otherwise require them.  Some day this option should go away
  # and CRLs should be uncondtionally mandatory in such cases.

  require_crls = False
  
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
    if not self.POW:
      self.POW = rpki.POW.derRead(rpki.POW.CMS_MESSAGE, self.get_DER())
    return self.POW

  def get_content(self):
    """
    Get the inner content of this CMS_object.
    """
    if self.content is None:
      raise rpki.exceptions.CMSContentNotSet, "Inner content of CMS object %r is not set" % self
    return self.content

  def set_content(self, content):
    """
    Set the (inner) content of this CMS_object, clearing the wrapper.
    """
    self.clear()
    self.content = content

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
    except:
      if self.print_on_der_error:
        rpki.log.debug("Problem parsing DER CMS message, might not really be DER: %r" % self.get_DER())
      raise rpki.exceptions.UnparsableCMSDER

    if cms.eContentType() != self.econtent_oid:
      raise rpki.exceptions.WrongEContentType, "Got CMS eContentType %s, expected %s" % (cms.eContentType(), self.econtent_oid)

    certs = [X509(POW = x) for x in cms.certs()]
    crls  = [CRL(POW = c) for c in cms.crls()]

    if self.debug_cms_certs:
      for x in certs:
        rpki.log.debug("Received CMS cert issuer %s subject %s SKI %s" % (x.getIssuer(), x.getSubject(), x.hSKI()))
      for c in crls:
        rpki.log.debug("Received CMS CRL issuer %r" % (c.getIssuer(),))

    store = rpki.POW.X509Store()

    trusted_ee = None

    for x in X509.normalize_chain(ta):
      if self.debug_cms_certs:
        rpki.log.debug("CMS trusted cert issuer %s subject %s SKI %s" % (x.getIssuer(), x.getSubject(), x.hSKI()))
      if not x.is_CA():
        assert trusted_ee is None, "Can't have two EE certs in the same validation chain"
        trusted_ee = x
      store.addTrust(x.get_POW())

    if trusted_ee:
      if self.debug_cms_certs:
        rpki.log.debug("Trusted CMS EE cert issuer %s subject %s SKI %s" % (trusted_ee.getIssuer(), trusted_ee.getSubject(), trusted_ee.hSKI()))
      if certs and (len(certs) > 1 or certs[0].getSubject() != trusted_ee.getSubject() or certs[0].getPublicKey() != trusted_ee.getPublicKey()):
        raise rpki.exceptions.UnexpectedCMSCerts, certs
      if crls:
        raise rpki.exceptions.UnexpectedCMSCRLs, crls
    else:
      if not certs:
        raise rpki.exceptions.MissingCMSEEcert, certs        
      if len(certs) > 1 or certs[0].is_CA():
        raise rpki.exceptions.UnexpectedCMSCerts, certs
      if not crls:
        if self.require_crls:
          raise rpki.exceptions.MissingCMSCRL, crls
        else:
          rpki.log.warn("MISSING CMS CRL!  Ignoring per self.require_crls setting")
      if len(crls) > 1:
        raise rpki.exceptions.UnexpectedCMSCRLs, crls

    try:
      content = cms.verify(store)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      if self.dump_on_verify_failure:
        if True:
          dbg = self.dumpasn1()
        else:
          dbg = cms.pprint()
        sys.stderr.write("CMS verification failed, dumping ASN.1 (%d octets):\n%s\n" % (len(self.get_DER()), dbg))
      raise rpki.exceptions.CMSVerificationFailed, "CMS verification failed"

    self.decode(content)
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

    try:
      cms = self.get_POW()
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      raise rpki.exceptions.UnparsableCMSDER

    if cms.eContentType() != self.econtent_oid:
      raise rpki.exceptions.WrongEContentType, "Got CMS eContentType %s, expected %s" % (cms.eContentType(), self.econtent_oid)

    content = cms.verify(rpki.POW.X509Store(), None, rpki.POW.CMS_NOCRL | rpki.POW.CMS_NO_SIGNER_CERT_VERIFY | rpki.POW.CMS_NO_ATTR_VERIFY | rpki.POW.CMS_NO_CONTENT_VERIFY)

    self.decode(content)
    return self.get_content()

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
      rpki.log.debug("Signing with cert issuer %s subject %s SKI %s" % (cert.getIssuer(), cert.getSubject(), cert.hSKI()))
      for i, c in enumerate(certs):
        rpki.log.debug("Additional cert %d issuer %s subject %s SKI %s" % (i, c.getIssuer(), c.getSubject(), c.hSKI()))

    cms = rpki.POW.CMS()

    cms.sign(cert.get_POW(),
             keypair.get_POW(),
             self.encode(),
             [x.get_POW() for x in certs],
             [c.get_POW() for c in crls],
             self.econtent_oid,
             rpki.POW.CMS_NOCERTS if no_certs else 0)

    self.POW = cms

class DER_CMS_object(CMS_object):
  """
  Class to hold CMS objects with DER-based content.
  """

  def encode(self):
    """
    Encode inner content for signing.
    """
    return self.get_content().toString()

  def decode(self, der):
    """
    Decode DER and set inner content.
    """
    obj = self.content_class()
    obj.fromString(der)
    self.content = obj

class SignedManifest(DER_CMS_object):
  """
  Class to hold a signed manifest.
  """

  pem_converter = PEM_converter("RPKI MANIFEST")
  content_class = rpki.manifest.Manifest
  econtent_oid = POWify_OID("id-ct-rpkiManifest")
  
  def getThisUpdate(self):
    """
    Get thisUpdate value from this manifest.
    """
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_content().thisUpdate.get())

  def getNextUpdate(self):
    """
    Get nextUpdate value from this manifest.
    """
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_content().nextUpdate.get())

  @classmethod
  def build(cls, serial, thisUpdate, nextUpdate, names_and_objs, keypair, certs, version = 0):
    """
    Build a signed manifest.
    """
    self = cls()
    filelist = []
    for name, obj in names_and_objs:
      d = rpki.POW.Digest(rpki.POW.SHA256_DIGEST)
      d.update(obj.get_DER())
      filelist.append((name.rpartition("/")[2], d.digest()))
    filelist.sort(key = lambda x: x[0])
    m = rpki.manifest.Manifest()
    m.version.set(version)
    m.manifestNumber.set(serial)
    m.thisUpdate.set(thisUpdate.toGeneralizedTime())
    m.nextUpdate.set(nextUpdate.toGeneralizedTime())
    m.fileHashAlg.set(rpki.oids.name2oid["id-sha256"])
    m.fileList.set(filelist)
    self.set_content(m)
    self.sign(keypair, certs)
    return self

class ROA(DER_CMS_object):
  """
  Class to hold a signed ROA.
  """

  pem_converter = PEM_converter("ROUTE ORIGIN ATTESTATION")
  content_class = rpki.roa.RouteOriginAttestation
  econtent_oid = POWify_OID("id-ct-routeOriginAttestation")

  @classmethod
  def build(cls, asn, ipv4, ipv6, keypair, certs, version = 0):
    """
    Build a ROA.
    """
    try:
      self = cls()
      r = rpki.roa.RouteOriginAttestation()
      r.version.set(version)
      r.asID.set(asn)
      r.ipAddrBlocks.set((a.to_roa_tuple() for a in (ipv4, ipv6) if a))
      self.set_content(r)
      self.sign(keypair, certs)
      return self
    except rpki.POW.pkix.DerError, e:
      rpki.log.debug("Encoding error while generating ROA %r: %s" % (self, e))
      rpki.log.debug("ROA inner content: %r" % (r.get(),))
      raise

class DeadDrop(object):
  """
  Dead-drop utility for storing copies of CMS messages for debugging or
  audit.  At the moment this uses Maildir mailbox format, as it has
  approximately the right properties and a number of useful tools for
  manipulating it already exist.
  """

  def __init__(self, name):
    self.maildir = mailbox.Maildir(name, factory = None, create = True)
    self.pid = os.getpid()

  def dump(self, obj):
    now = time.time()
    msg = email.mime.application.MIMEApplication(obj.get_DER(), "x-rpki")
    msg["Date"] = email.utils.formatdate(now)
    msg["Subject"] = "Process %s dump of %r" % (self.pid, obj)
    msg["Message-ID"] = email.utils.make_msgid()
    msg["X-RPKI-PID"] = str(self.pid)
    msg["X-RPKI-Object"] = repr(obj)
    msg["X-RPKI-Timestamp"] = "%f" % now
    self.maildir.add(msg)

class XML_CMS_object(CMS_object):
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

  def encode(self):
    """
    Encode inner content for signing.
    """
    return lxml.etree.tostring(self.get_content(), pretty_print = True, encoding = self.encoding, xml_declaration = True)

  def decode(self, xml):
    """
    Decode XML and set inner content.
    """
    self.content = lxml.etree.fromstring(xml)

  def pretty_print_content(self):
    """
    Pretty print XML content of this message.
    """
    return lxml.etree.tostring(self.get_content(), pretty_print = True, encoding = self.encoding, xml_declaration = True)

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
    self.set_content(msg.toXML())
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
    self.schema_check()
    return self.saxify(self.get_content())

class CRL(DER_object):
  """
  Class to hold a Certificate Revocation List.
  """

  formats = ("DER", "POW", "POWpkix")
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
    if self.POWpkix:
      self.DER = self.POWpkix.toString()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """
    Get the rpki.POW value of this CRL.
    """
    self.check()
    if not self.POW:
      self.POW = rpki.POW.derRead(rpki.POW.X509_CRL, self.get_DER())
    return self.POW

  def get_POWpkix(self):
    """
    Get the rpki.POW.pkix value of this CRL.
    """
    self.check()
    if not self.POWpkix:
      crl = rpki.POW.pkix.CertificateList()
      crl.fromString(self.get_DER())
      self.POWpkix = crl
    return self.POWpkix

  def getThisUpdate(self):
    """
    Get thisUpdate value from this CRL.
    """
    return rpki.sundial.datetime.fromASN1tuple(self.get_POWpkix().getThisUpdate())

  def getNextUpdate(self):
    """
    Get nextUpdate value from this CRL.
    """
    return rpki.sundial.datetime.fromASN1tuple(self.get_POWpkix().getNextUpdate())

  def getIssuer(self):
    """
    Get issuer value of this CRL.
    """
    return self.get_POW().getIssuer()

  @classmethod
  def generate(cls, keypair, issuer, serial, thisUpdate, nextUpdate, revokedCertificates, version = 1, digestType = "sha256WithRSAEncryption"):
    """
    Generate a new CRL.
    """
    crl = rpki.POW.pkix.CertificateList()
    crl.setVersion(version)
    crl.setIssuer(issuer.get_POWpkix().getSubject())
    crl.setThisUpdate(thisUpdate.toASN1tuple())
    crl.setNextUpdate(nextUpdate.toASN1tuple())
    if revokedCertificates:
      crl.setRevokedCertificates(revokedCertificates)
    crl.setExtensions(
      ((rpki.oids.name2oid["authorityKeyIdentifier"], False, (issuer.get_SKI(), (), None)),
       (rpki.oids.name2oid["cRLNumber"], False, serial)))
    crl.sign(keypair.get_POW(), digestType)
    return cls(POWpkix = crl)
