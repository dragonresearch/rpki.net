# $Id$

"""
One X.509 implementation to rule them all and in the darkness hide the
twisty maze of partially overlapping X.509 support packages in Python.

There are several existing packages, none of which do quite what I
need, due to age, lack of documentation, specialization, or lack of
foresight on somebody's part (perhaps mine).  This module attempts to
bring together the functionality I need in a way that hides at least
some of the nasty details.  This involves a lot of format conversion.
"""

import POW, tlslite.api, POW.pkix, base64

class PEM_converter(object):
  """
  Convert between DER and PEM encodings for various kinds of ASN.1 data.
  """

  def __init__(self, kind):    # "CERTIFICATE", "RSA PRIVATE KEY", ...
    self.b = "-----BEGIN %s-----" % kind
    self.e = "-----END %s-----"   % kind

  def toDER(self, pem):
    lines = pem.splitlines(0)
    while lines and lines.pop(0) != self.b:
      pass
    while lines and lines.pop(-1) != self.e:
      pass
    assert lines
    return base64.b64decode("".join(lines))

  def toPEM(self, der):
    b64 =  base64.b64encode(der)
    pem = self.b + "\n"
    while len(b64) > 64:
      pem += b64[0:64] + "\n"
      b64 = b64[64:]
    return pem + b64 + "\n" + self.e + "\n"

class DER_object(object):
  """
  Virtual class to hold a generic DER object.
  """

  formats = ("DER",)
  pem_converter = None
  other_clear = ()

  def empty(self):
    for a in self.formats:
      if getattr(self, a, None) is not None:
        return False
    return True

  def clear(self):
    for a in self.formats + self.other_clear:
      setattr(self, a, None)

  def __init__(self, **kw):
    self.clear()
    if len(kw):
      self.set(**kw)

  def set(self, **kw):
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
    assert not self.empty()
    if self.DER:
      return self.DER
    raise RuntimeError, "No conversion path to DER available"

  def get_PEM(self):
    return self.pem_converter.toPEM(self.get_DER())

class X509(DER_object):
  """
  Class to hold all the different representations of X.509 certs we're
  using and convert between them.
  """

  formats = ("DER", "POW", "POWpkix", "tlslite")
  pem_converter = PEM_converter("CERTIFICATE")
  other_clear = ("POW_extensions",)
  
  def get_DER(self):
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
    assert not self.empty()
    if not self.POW:
      self.POW = POW.derRead(POW.X509_CERTIFICATE, self.get_DER())
    return self.POW

  def get_POWpkix(self):
    assert not self.empty()
    if not self.POWpkix:
      cert = POW.pkix.Certificate()
      cert.fromString(self.get_DER())
      self.POWpkix = cert
    return self.POWpkix

  def get_tlslite(self):
    assert not self.empty()
    if not self.tlslite:
      cert = tlslite.api.X509()
      cert.parseBinary(self.get_DER())
      self.tlslite = cert
    return self.tlslite

  def getIssuer(self):
    return self.get_POW().getIssuer()

  def getSubject(self):
    return self.get_POW().getSubject()

  def get_POW_extensions(self):
    if not self.POW_extensions:
      cert = self.get_POW()
      exts = {}
      for i in range(cert.countExtensions()):
        x = cert.getExtension(i)
        exts[x[0]] = x[2]
      self.POW_extensions = exts
    return self.POW_extensions
    
  def getAKI(self):
    return self.get_POW_extensions().get("authorityKeyIdentifier")

  def getSKI(self):
    return self.get_POW_extensions().get("subjectKeyIdentifier")

class X509_chain(list):
  """
  Collection of certs with sorting and conversion functions
  for various packages.
  """

  def chainsort(self):
    """
    Sort a bag of certs into a chain, leaf first.  Various other
    routines want their certs presented in this order.
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
    assert len(chain) == 1
    while bag:
      cert = subject_map[chain[-1].getIssuer()]
      chain.append(cert)
      bag.remove(cert)
    self[:] = chain

  def tlslite_certChain(self):
    return tlslite.api.X509CertChain([x.get_tlslite() for x in self])

  def tlslite_trustList(self):
    return [x.get_tlslite() for x in self]

  def clear(self):
    self[:] = []

  def load_from_PEM(self, files):
    self.extend([X509(PEM_file=f) for f in files])

  def load_from_DER(self, files):
    self.extend([X509(DER_file=f) for f in files])

class PKCS10_Request(DER_object):
  """
  Class to hold a PKCS #10 request.
  """

  formats = ("DER", "POWpkix")
  pem_converter = PEM_converter("CERTIFICATE REQUEST")
  
  def get_DER(self):
    assert not self.empty()
    if self.DER:
      return self.DER
    if self.POWpkix:
      self.DER = self.POWpkix.toString()
      return self.get_DER()
    raise RuntimeError

  def get_POWpkix(self):
    assert not self.empty()
    if not self.POWpkix:
      req = POW.pkix.CertificationRequest()
      req.fromString(self.get_DER())
      self.POWpkix = req
    return self.POWpkix
