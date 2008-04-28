# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""One X.509 implementation to rule them all...

...and in the darkness hide the twisty maze of partially overlapping
X.509 support packages in Python.

There are several existing packages, none of which do quite what I
need, due to age, lack of documentation, specialization, or lack of
foresight on somebody's part (perhaps mine).  This module attempts to
bring together the functionality I need in a way that hides at least
some of the nasty details.  This involves a lot of format conversion.
"""

import POW, tlslite.api, POW.pkix, base64, lxml.etree, os
import rpki.exceptions, rpki.resource_set, rpki.oids, rpki.sundial
import rpki.manifest, rpki.roa

def calculate_SKI(public_key_der):
  """Calculate the SKI value given the DER representation of a public
  key, which requires first peeling the ASN.1 wrapper off the key.
  """
  k = POW.pkix.SubjectPublicKeyInfo()
  k.fromString(public_key_der)
  d = POW.Digest(POW.SHA1_DIGEST)
  d.update(k.subjectPublicKey.get())
  return d.digest()

class PEM_converter(object):
  """Convert between DER and PEM encodings for various kinds of ASN.1 data."""

  def __init__(self, kind):    # "CERTIFICATE", "RSA PRIVATE KEY", ...
    """Initialize PEM_converter."""
    self.b = "-----BEGIN %s-----" % kind
    self.e = "-----END %s-----"   % kind

  def looks_like_PEM(self, text):
    """Guess whether text looks like a PEM encoding."""
    b = text.find(self.b)
    return b >= 0 and text.find(self.e) > b + len(self.b)

  def to_DER(self, pem):
    """Convert from PEM to DER."""
    lines = [line.strip() for line in pem.splitlines(0)]
    while lines and lines.pop(0) != self.b:
      pass
    while lines and lines.pop(-1) != self.e:
      pass
    if not lines:
      raise rpki.exceptions.EmptyPEM, "Could not find PEM in:\n%s" % pem
    return base64.b64decode("".join(lines))

  def to_PEM(self, der):
    """Convert from DER to PEM."""
    b64 =  base64.b64encode(der)
    pem = self.b + "\n"
    while len(b64) > 64:
      pem += b64[0:64] + "\n"
      b64 = b64[64:]
    return pem + b64 + "\n" + self.e + "\n"

class DER_object(object):
  """Virtual class to hold a generic DER object."""

  ## Formats supported in this object
  formats = ("DER",)

  ## PEM converter for this object
  pem_converter = None

  ## Other attributes that self.clear() should whack
  other_clear = ()

  ## @var DER
  ## DER value of this object

  def empty(self):
    """Test whether this object is empty."""
    for a in self.formats:
      if getattr(self, a, None) is not None:
        return False
    return True

  def clear(self):
    """Make this object empty."""
    for a in self.formats + self.other_clear:
      setattr(self, a, None)

  def __init__(self, **kw):
    """Initialize a DER_object."""
    self.clear()
    if len(kw):
      self.set(**kw)

  def set(self, **kw):
    """Set this object by setting one of its known formats.

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
      if name in ("PEM_file", "DER_file", "Auto_file"):
        f = open(kw[name], "rb")
        value = f.read()
        f.close()
        if name == "PEM_file" or (name == "Auto_file" and self.pem_converter.looks_like_PEM(value)):
          value = self.pem_converter.to_DER(value)
        self.clear()
        self.DER = value
        return
    raise rpki.exceptions.DERObjectConversionError, "Can't honor conversion request %s" % repr(kw)
  
  def get_DER(self):
    """Get the DER value of this object.

    Subclasses will almost certainly override this method.
    """
    assert not self.empty()
    if self.DER:
      return self.DER
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_Base64(self):
    """Get the Base64 encoding of the DER value of this object."""
    return base64.b64encode(self.get_DER())

  def get_PEM(self):
    """Get the PEM representation of this object."""
    return self.pem_converter.to_PEM(self.get_DER())

  def __cmp__(self, other):
    """Compare two DER-encoded objects."""
    return cmp(self.get_DER(), other.get_DER())

  def hSKI(self):
    """Return hexadecimal string representation of SKI for this
    object.  Only work for subclasses that implement get_SKI().
    """
    return ":".join(("%02X" % ord(i) for i in self.get_SKI()))

  def gSKI(self):
    """Calculate g(SKI) for this object.  Only work for subclasses
    that implement get_SKI().
    """
    return base64.urlsafe_b64encode(self.get_SKI()).rstrip("=")

  def get_AKI(self):
    """Get the AKI extension from this object.  Only works for subclasses that support getExtension()."""
    return (self.get_POWpkix().getExtension(rpki.oids.name2oid["authorityKeyIdentifier"]) or ((), 0, None))[2]

  def get_SKI(self):
    """Get the SKI extension from this object.  Only works for subclasses that support getExtension()."""
    return (self.get_POWpkix().getExtension(rpki.oids.name2oid["subjectKeyIdentifier"]) or ((), 0, None))[2]

  def get_SIA(self):
    """Get the SIA extension from this object.  Only works for subclasses that support getExtension()."""
    return (self.get_POWpkix().getExtension(rpki.oids.name2oid["subjectInfoAccess"]) or ((), 0, None))[2]

  def get_AIA(self):
    """Get the SIA extension from this object.  Only works for subclasses that support getExtension()."""
    return (self.get_POWpkix().getExtension(rpki.oids.name2oid["subjectInfoAccess"]) or ((), 0, None))[2]

  def get_3779resources(self):
    """Get RFC 3779 resources as rpki.resource_set objects.
    Only works for subclasses that support getExtensions().
    """
    resources = rpki.resource_set.resource_bag.from_rfc3779_tuples(self.get_POWpkix().getExtensions())
    try:
      resources.valid_until = self.getNotAfter()
    except AttributeError:
      pass
    return resources

  @classmethod
  def from_sql(cls, x):
    """Convert from SQL storage format."""
    return cls(DER = x)

  def to_sql(self):
    """Convert to SQL storage format."""
    return self.get_DER()

  def dumpasn1(self):
    """Pretty print an ASN.1 DER object using cryptlib dumpasn1 tool.
    Use a temporary file rather than popen4() because dumpasn1 uses
    seek() when decoding ASN.1 content nested in OCTET STRING values.
    """

    ret = None
    fn = "dumpasn1.tmp"
    try:
      f = open(fn, "wb")
      f.write(self.get_DER())
      f.close()
      f = os.popen("dumpasn1 2>&1 -a " + fn)
      ret = "\n".join(x for x in f.read().splitlines() if x.startswith(" "))
      f.close()
    finally:
      os.unlink(fn)
    return ret

class X509(DER_object):
  """X.509 certificates.

  This class is designed to hold all the different representations of
  X.509 certs we're using and convert between them.  X.509 support in
  Python a nasty maze of half-cooked stuff (except perhaps for
  cryptlib, which is just different).  Users of this module should not
  have to care about this implementation nightmare.
  """

  formats = ("DER", "POW", "POWpkix", "tlslite")
  pem_converter = PEM_converter("CERTIFICATE")
  
  def get_DER(self):
    """Get the DER value of this certificate."""
    assert not self.empty()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWrite()
      return self.get_DER()
    if self.POWpkix:
      self.DER = self.POWpkix.toString()
      return self.get_DER()
    if self.tlslite:
      self.DER = self.tlslite.writeBytes()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """Get the POW value of this certificate."""
    assert not self.empty()
    if not self.POW:
      self.POW = POW.derRead(POW.X509_CERTIFICATE, self.get_DER())
    return self.POW

  def get_POWpkix(self):
    """Get the POW.pkix value of this certificate."""
    assert not self.empty()
    if not self.POWpkix:
      cert = POW.pkix.Certificate()
      cert.fromString(self.get_DER())
      self.POWpkix = cert
    return self.POWpkix

  def get_tlslite(self):
    """Get the tlslite value of this certificate."""
    assert not self.empty()
    if not self.tlslite:
      cert = tlslite.api.X509()
      cert.parseBinary(self.get_DER())
      self.tlslite = cert
    return self.tlslite

  def getIssuer(self):
    """Get the issuer of this certificate."""
    return self.get_POW().getIssuer()

  def getSubject(self):
    """Get the subject of this certificate."""
    return self.get_POW().getSubject()

  def getNotBefore(self):
    """Get the inception time of this certificate."""
    return rpki.sundial.datetime.fromASN1tuple(self.get_POWpkix().tbs.validity.notBefore.get())

  def getNotAfter(self):
    """Get the expiration time of this certificate."""
    return rpki.sundial.datetime.fromASN1tuple(self.get_POWpkix().tbs.validity.notAfter.get())

  def getSerial(self):
    """Get the serial number of this certificate."""
    return self.get_POW().getSerial()

  def getPublicKey(self):
    """Extract the public key from this certificate."""
    return RSApublic(DER = self.get_POWpkix().tbs.subjectPublicKeyInfo.toString())

  def issue(self, keypair, subject_key, serial, sia, aia, crldp, notAfter,
            cn = None, resources = None, is_ca = True):
    """Issue a certificate."""

    now = rpki.sundial.now()
    aki = self.get_SKI()
    ski = subject_key.get_SKI()

    if cn is None:
      cn = "".join(("%02X" % ord(i) for i in ski))

    # if notAfter is None: notAfter = now + rpki.sundial.timedelta(days = 30)

    cert = POW.pkix.Certificate()
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

    if resources is not None and resources.as:
      exts.append(["sbgp-autonomousSysNum", True, (resources.as.to_rfc3779_tuple(), None)])

    if resources is not None and (resources.v4 or resources.v6):
      exts.append(["sbgp-ipAddrBlock", True, [x for x in (resources.v4.to_rfc3779_tuple(), resources.v6.to_rfc3779_tuple()) if x is not None]])

    for x in exts:
      x[0] = rpki.oids.name2oid[x[0]]
    cert.setExtensions(exts)

    cert.sign(keypair.get_POW(), POW.SHA256_DIGEST)

    return X509(POWpkix = cert)

  @classmethod
  def normalize_chain(cls, chain):
    """Normalize a chain of certificates into a tuple of X509 objects.
    Given all the glue certificates needed for BPKI cross
    certification, it's easiest to allow sloppy arguments to the HTTPS
    and CMS validation methods and provide a single method that
    normalizes the allowed cases.  So this method allows X509, None,
    lists, and tuples, and returns a tuple of X509 objects.
    """
    if isinstance(chain, cls):
      chain = (chain,)
    return tuple(x for x in chain if x is not None)

class PKCS10(DER_object):
  """Class to hold a PKCS #10 request."""

  formats = ("DER", "POWpkix")
  pem_converter = PEM_converter("CERTIFICATE REQUEST")
  
  def get_DER(self):
    """Get the DER value of this certification request."""
    assert not self.empty()
    if self.DER:
      return self.DER
    if self.POWpkix:
      self.DER = self.POWpkix.toString()
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POWpkix(self):
    """Get the POW.pkix value of this certification request."""
    assert not self.empty()
    if not self.POWpkix:
      req = POW.pkix.CertificationRequest()
      req.fromString(self.get_DER())
      self.POWpkix = req
    return self.POWpkix

  def getPublicKey(self):
    """Extract the public key from this certification request."""
    return RSApublic(DER = self.get_POWpkix().certificationRequestInfo.subjectPublicKeyInfo.toString())

  def check_valid_rpki(self):
    """Check this certification request to see whether it's a valid
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
        raise rpki.exceptions.BadPKCS10, "Certificate request includes bad SIA component: %s" % repr(location)

    # This one is an implementation restriction.  I don't yet
    # understand what the spec is telling me to do in this case.
    assert "subjectInfoAccess" in req_exts, "Can't (yet) handle PKCS #10 without an SIA extension"

  @classmethod
  def create_ca(cls, keypair, sia = None):
    """Create a new request for a given keypair, including given SIA value."""
    exts = [["basicConstraints", True, (1, None)],
            ["keyUsage",         True, (0, 0, 0, 0, 0, 1, 1)]]
    if sia is not None:
      exts.append(["subjectInfoAccess", False, sia])
    for x in exts:
      x[0] = rpki.oids.name2oid[x[0]]
    return cls.create(keypair, exts)

  @classmethod
  def create(cls, keypair, exts = None):
    """Create a new request for a given keypair, including given extensions."""
    cn = "".join(("%02X" % ord(i) for i in keypair.get_SKI()))
    req = POW.pkix.CertificationRequest()
    req.certificationRequestInfo.version.set(0)
    req.certificationRequestInfo.subject.set((((rpki.oids.name2oid["commonName"],
                                                ("printableString", cn)),),))
    if exts is not None:
      req.setExtensions(exts)
    req.sign(keypair.get_POW(), POW.SHA256_DIGEST)
    return cls(POWpkix = req)

class RSA(DER_object):
  """Class to hold an RSA key pair."""

  formats = ("DER", "POW", "tlslite")
  pem_converter = PEM_converter("RSA PRIVATE KEY")
  
  def get_DER(self):
    """Get the DER value of this keypair."""
    assert not self.empty()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWrite(POW.RSA_PRIVATE_KEY)
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """Get the POW value of this keypair."""
    assert not self.empty()
    if not self.POW:
      self.POW = POW.derRead(POW.RSA_PRIVATE_KEY, self.get_DER())
    return self.POW

  def get_tlslite(self):
    """Get the tlslite value of this keypair."""
    assert not self.empty()
    if not self.tlslite:
      self.tlslite = tlslite.api.parsePEMKey(self.get_PEM(), private=True)
    return self.tlslite

  def generate(self, keylength = 2048):
    """Generate a new keypair."""
    self.clear()
    self.set(POW=POW.Asymmetric(POW.RSA_CIPHER, keylength))

  def get_public_DER(self):
    """Get the DER encoding of the public key from this keypair."""
    return self.get_POW().derWrite(POW.RSA_PUBLIC_KEY)

  def get_SKI(self):
    """Calculate the SKI of this keypair."""
    return calculate_SKI(self.get_public_DER())

  def get_RSApublic(self):
    """Convert the public key of this keypair into a RSApublic object."""
    return RSApublic(DER = self.get_public_DER())

class RSApublic(DER_object):
  """Class to hold an RSA public key."""

  formats = ("DER", "POW")
  pem_converter = PEM_converter("RSA PUBLIC KEY")
  
  def get_DER(self):
    """Get the DER value of this public key."""
    assert not self.empty()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWrite(POW.RSA_PUBLIC_KEY)
      return self.get_DER()
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_POW(self):
    """Get the POW value of this public key."""
    assert not self.empty()
    if not self.POW:
      self.POW = POW.derRead(POW.RSA_PUBLIC_KEY, self.get_DER())
    return self.POW

  def get_SKI(self):
    """Calculate the SKI of this public key."""
    return calculate_SKI(self.get_DER())

def POWify(oid):
  """Utility function to convert tuple form of an OID to
  the dotted-decimal string form that POW uses.
  """
  if isinstance(oid, str):
    return POWify(rpki.oids.name2oid[oid])
  else:
    return ".".join(str(i) for i in oid)

class CMS_object(DER_object):
  """Class to hold a CMS-wrapped object.

  CMS-wrapped objects are a little different from the other DER_object
  types because the signed object is CMS wrapping inner content that's
  also ASN.1, and due to our current minimal support for CMS we can't
  just handle this as a pretty composite object.  So, for now anyway,
  a CMS_object is the outer CMS wrapped object so that the usual DER
  and PEM operations do the obvious things, and the inner content is
  handle via separate methods.
  """

  formats = ("DER",)
  other_clear = ("content",)
  econtent_oid = POWify("id-data")
  
  dump_on_verify_failure = False
  debug_cms_certs = False

  def get_DER(self):
    """Get the DER value of this CMS_object."""
    assert not self.empty()
    if self.DER:
      return self.DER
    raise rpki.exceptions.DERObjectConversionError, "No conversion path to DER available"

  def get_content(self):
    """Get the inner content of this CMS_object."""
    assert self.content is not None
    return self.content

  def set_content(self, content):
    """Set the (inner) content of this CMS_object, clearing the wrapper."""
    self.clear()
    self.content = content

  def verify(self, ta):
    """Verify CMS wrapper and store inner content."""

    cms = POW.derRead(POW.CMS_MESSAGE, self.get_DER())

    if cms.eContentType() != self.econtent_oid:
      raise rpki.exceptions.WrongEContentType, "Got CMS eContentType %s, expected %s" % (cms.eContentType(), self.econtent_oid)

    store = POW.X509Store()

    ta = X509.normalize_chain(ta)

    for x in ta:
      if self.debug_cms_certs:
        rpki.log.debug("CMS trusted cert issuer %s subject %s" % (x.getIssuer(), x.getSubject()))
      store.addTrust(x.get_POW())

    if self.debug_cms_certs:
      for x in cms.certs():
        rpki.log.debug("Received CMS cert issuer %s subject %s" % (x.getIssuer(), x.getSubject()))

    try:
      content = cms.verify(store)
    except:
      if self.dump_on_verify_failure:
        rpki.log.debug("CMS verification failed, dumping ASN.1:\n" + self.dumpasn1())
      raise rpki.exceptions.CMSVerificationFailed, "CMS verification failed"

    self.decode(content)
    return self.get_content()

  def sign(self, keypair, certs, crls = None, no_certs = False):
    """Sign and wrap inner content."""

    if isinstance(certs, X509):
      cert = certs
      certs = ()
    else:
      cert = certs[0]
      certs = certs[1:]

    cms = POW.CMS()
    cms.sign(cert.get_POW(),
             keypair.get_POW(),
             self.encode(),
             [x.get_POW() for x in certs],
             crls,
             self.econtent_oid,
             POW.CMS_NOCERTS if no_certs else 0)
    self.DER = cms.derWrite()

class DER_CMS_object(CMS_object):
  """Class to hold CMS objects with DER-based content."""

  def encode(self):
    """Encode inner content for signing."""
    return self.get_content().toString()

  def decode(self, der):
    """Decode DER and set inner content."""
    obj = self.content_class()
    obj.fromString(der)
    self.content = obj

class SignedManifest(DER_CMS_object):
  """Class to hold a signed manifest."""

  pem_converter = PEM_converter("RPKI MANIFEST")
  content_class = rpki.manifest.Manifest
  econtent_oid = POWify("id-ct-rpkiManifest")
  
  def getThisUpdate(self):
    """Get thisUpdate value from this manifest."""
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_content().thisUpdate.get())

  def getNextUpdate(self):
    """Get nextUpdate value from this manifest."""
    return rpki.sundial.datetime.fromGeneralizedTime(self.get_content().nextUpdate.get())

  @classmethod
  def build(cls, serial, thisUpdate, nextUpdate, names_and_objs, keypair, certs, version = 0):
    """Build a signed manifest."""
    self = cls()
    filelist = []
    for name, obj in names_and_objs:
      d = POW.Digest(POW.SHA256_DIGEST)
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
  """Class to hold a signed ROA."""

  pem_converter = PEM_converter("ROUTE ORIGIN ATTESTATION")
  content_class = rpki.roa.RouteOriginAttestation
  econtent_oid = POWify("id-ct-routeOriginAttestation")

  @classmethod
  def build(cls, as_number, exact_match, ipv4, ipv6, keypair, certs, version = 0):
    """Build a ROA."""
    self = cls()
    r = rpki.roa.RouteOriginAttestation()
    r.version.set(version)
    r.asID.set(as_number)
    r.exactMatch.set(exact_match)
    r.ipAddrBlocks.set((a.to_roa_tuple() for a in (ipv4, ipv6) if a))
    self.set_content(r)
    self.sign(keypair, certs)
    return self

class XML_CMS_object(CMS_object):
  """Class to hold CMS-wrapped XML protocol data."""

  econtent_oid = POWify("id-ct-xml")

  def encode(self):
    """Encode inner content for signing."""
    return lxml.etree.tostring(self.get_content(), pretty_print = True, encoding = self.encoding, xml_declaration = True)

  def decode(self, xml):
    """Decode XML and set inner content."""
    self.content = lxml.etree.fromstring(xml)

  def pretty_print_content(self):
    """Pretty print XML content of this message."""
    return lxml.etree.tostring(self.get_content(), pretty_print = True, encoding = self.encoding, xml_declaration = True)

  def schema_check(self):
    """Handle XML RelaxNG schema check."""
    try:
      self.schema.assertValid(self.get_content())
    except lxml.etree.DocumentInvalid:
      rpki.log.error("PDU failed schema check: " + self.pretty_print_content())
      raise

  @classmethod
  def wrap(cls, msg, keypair, certs, pretty_print = False):
    """Build a CMS-wrapped XML PDU and return its DER encoding."""
    self = cls()
    self.set_content(msg.toXML())
    self.schema_check()
    self.sign(keypair, certs)
    if pretty_print:
      return self.get_DER(), self.pretty_print_content()
    else:
      return self.get_DER()

  @classmethod
  def unwrap(cls, der, ta, pretty_print = False):
    """Unwrap a CMS-wrapped XML PDU and return Python objects."""
    self = cls(DER = der)
    CMS_object.verify(self, ta)
    self.schema_check()
    msg = self.saxify(self.get_content())
    if pretty_print:
      return msg, self.pretty_print_content()
    else:
      return msg

  def verify(self, ta):
    raise NotImplementedError, "Should not be calling this, it's obsolete"

class CRL(DER_object):
  """Class to hold a Certificate Revocation List."""

  formats = ("DER", "POW", "POWpkix")
  pem_converter = PEM_converter("X509 CRL")
  
  def get_DER(self):
    """Get the DER value of this CRL."""
    assert not self.empty()
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
    """Get the POW value of this CRL."""
    assert not self.empty()
    if not self.POW:
      self.POW = POW.derRead(POW.X509_CRL, self.get_DER())
    return self.POW

  def get_POWpkix(self):
    """Get the POW.pkix value of this CRL."""
    assert not self.empty()
    if not self.POWpkix:
      crl = POW.pkix.CertificateList()
      crl.fromString(self.get_DER())
      self.POWpkix = crl
    return self.POWpkix

  def getThisUpdate(self):
    """Get thisUpdate value from this CRL."""
    return rpki.sundial.datetime.fromASN1tuple(self.get_POWpkix().getThisUpdate())

  def getNextUpdate(self):
    """Get nextUpdate value from this CRL."""
    return rpki.sundial.datetime.fromASN1tuple(self.get_POWpkix().getNextUpdate())

  @classmethod
  def generate(cls, keypair, issuer, serial, thisUpdate, nextUpdate, revokedCertificates, version = 1, digestType = "sha256WithRSAEncryption"):
    crl = POW.pkix.CertificateList()
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
