# $Id$

"""One X.509 implementation to rule them all...

...and in the darkness hide the twisty maze of partially overlapping
X.509 support packages in Python.

There are several existing packages, none of which do quite what I
need, due to age, lack of documentation, specialization, or lack of
foresight on somebody's part (perhaps mine).  This module attempts to
bring together the functionality I need in a way that hides at least
some of the nasty details.  This involves a lot of format conversion.
"""

import POW, tlslite.api, POW.pkix, base64

class PEM_converter(object):
  """Convert between DER and PEM encodings for various kinds of ASN.1 data."""

  def __init__(self, kind):    # "CERTIFICATE", "RSA PRIVATE KEY", ...
    self.b = "-----BEGIN %s-----" % kind
    self.e = "-----END %s-----"   % kind

  def toDER(self, pem):
    """Convert from PEM to DER."""
    lines = pem.splitlines(0)
    while lines and lines.pop(0) != self.b:
      pass
    while lines and lines.pop(-1) != self.e:
      pass
    assert lines
    return base64.b64decode("".join(lines))

  def toPEM(self, der):
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
    name = kw.keys()[0]
    if len(kw) == 1:
      if name in self.formats:
        self.clear()
        setattr(self, name, kw[name])
        return
      if name in ("PEM_file", "DER_file"):
        f = open(kw[name], "r")
        text = f.read()
        f.close()
        if name == "PEM_file":
          text = self.pem_converter.toDER(text)
        self.clear()
        self.DER = text
        return
    raise TypeError
  
  def get_DER(self):
    """Get the DER value of this object.

    Subclasses will almost certainly override this method.
    """
    assert not self.empty()
    if self.DER:
      return self.DER
    raise RuntimeError, "No conversion path to DER available"

  def get_PEM(self):
    """Get the PEM representation of this object."""
    return self.pem_converter.toPEM(self.get_DER())

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
  other_clear = ("POW_extensions",)
  
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
    raise RuntimeError

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

  def _get_POW_extensions(self):
    """Parse extensions from the POW value of this certificate.

    Build a dictionary to ease lookup, and cache the result.
    """
    if not self.POW_extensions:
      cert = self.get_POW()
      exts = {}
      for i in range(cert.countExtensions()):
        x = cert.getExtension(i)
        exts[x[0]] = x[2]
      self.POW_extensions = exts
    return self.POW_extensions
    
  def getAKI(self):
    """Get the AKI extension from this certificate."""
    return self._get_POW_extensions().get("authorityKeyIdentifier")

  def getSKI(self):
    """Get the SKI extension from this certificate."""
    return self._get_POW_extensions().get("subjectKeyIdentifier")

class X509_chain(list):
  """Collections of certs.

  This class provides sorting and conversion functions for various
  packages.
  """

  def chainsort(self):
    """Sort a bag of certs into a chain, leaf first.

    Various other routines want their certs presented in this order.
    """
    bag = self[:]
    issuer_names = [x.getIssuer() for x in bag]
    subject_map = dict([(x.getSubject(), x) for x in bag])
    chain = []
    for subject in subject_map:
      if subject not in issuer_names:
        cert = subject_map[subject]
        chain.append(cert)
        bag.remove(cert)
    if len(chain) != 1:
      raise RuntimeError, "Certificates in bag don't form a proper chain"
    while bag:
      cert = subject_map[chain[-1].getIssuer()]
      chain.append(cert)
      bag.remove(cert)
    self[:] = chain

  def tlslite_certChain(self):
    """Return a certChain in the format tlslite likes."""
    self.chainsort()
    return tlslite.api.X509CertChain([x.get_tlslite() for x in self])

  def tlslite_trustList(self):
    """Return a trustList in the format tlslite likes."""
    return [x.get_tlslite() for x in self]

  def clear(self):
    """Drop all certs from this bag onto the floor."""
    self[:] = []

  def load_from_PEM(self, files):
    """Load a set of certs from a list of PEM files."""
    self.extend([X509(PEM_file=f) for f in files])

  def load_from_DER(self, files):
    """Load a set of certs from a list of DER files."""
    self.extend([X509(DER_file=f) for f in files])

class PKCS10_Request(DER_object):
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
    raise RuntimeError

  def get_POWpkix(self):
    """Get the POW.pkix value of this certification request."""
    assert not self.empty()
    if not self.POWpkix:
      req = POW.pkix.CertificationRequest()
      req.fromString(self.get_DER())
      self.POWpkix = req
    return self.POWpkix

class RSA_Keypair(DER_object):
  """Class to hold an RSA key pair.

  This may need to be split into public and private key classes.
  """

  formats = ("DER", "POW", "tlslite")
  pem_converter = PEM_converter("RSA PRIVATE KEY")
  
  def get_DER(self):
    assert not self.empty()
    if self.DER:
      return self.DER
    if self.POW:
      self.DER = self.POW.derWrite()
      return self.get_DER()
    raise RuntimeError

  def get_POW(self):
    assert not self.empty()
    if not self.POW:
      self.POW = POW.derRead(POW.RSA_PRIVATE_KEY, self.get_DER())
    return self.POW

  def get_tlslite(self):
    assert not self.empty()
    if not self.tlslite:
      self.tlslite = tlslite.api.parsePEMKey(self.get_PEM(), private=True)
    return self.tlslite
