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

import POW, tlslite.api, POW.pkix

class X509(object):
  """
  Class to hold all the different representations of X.509 certs we're
  using and convert between them.
  """

  DER = None
  PEM = None
  POW = None
  POWpkix = None
  tlslite = None

  def empty(self):
    return self.DER is None and self.PEM is None and self.POW is None and self.POWpkix is None and self.tlslite is None

  def clear(self):
    self.DER = None
    self.PEM = None
    self.POW = None
    self.POWpkix = None
    self.tlslite = None

  def __init__(self, **kw):
    if len(kw):
      self.set(**kw)

  def set(self, **kw):
    name = kw.keys()[0]
    if len(kw) == 1:
      if name in ("DER", "PEM", "POW", "POWpkix", "tlslite"):
        self.clear()
        setattr(self, name, kw[name])
        return
      if name in ("PEM_file", "DER_file"):
        f = open(kw[name], "r")
        text = f.read()
        f.close()
        self.clear()
        if name == "PEM_file":
          self.PEM = text
        else:
          self.DER = text
        return
    raise RuntimeError                  # Should create our own exception classes

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
    if self.PEM:
      self.POW = POW.pemRead(POW.X509_CERTIFICATE, self.PEM)
      return self.get_DER()
    raise RuntimeError

  def get_POW(self):
    assert not self.empty()
    if not self.POW:
      self.POW = POW.derRead(POW.X509_CERTIFICATE, self.get_DER())
    return self.POW

  def get_PEM(self):
    assert not self.empty()
    if not self.PEM:
      self.PEM = self.get_POW().pemWrite()
    return self.PEM

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
    return self.get_POW_extensions()["authorityKeyIdentifier"]

  def getSKI(self):
    return self.get_POW_extensions()["subjectKeyIdentifier"]

def sort_chain(bag):
  """
  Sort a bag of certs into a chain, leaf first.  Various other routines
  want their certs presented in this order.
  """

  issuer_names = [x.getIssuer() for x in bag]
  subject_map = dict([(x.getSubject(), x) for x in bag])
  chain = list(bag)
  issuers = []

  for subject in subject_map:
    if subject in issuer_names:
      cert = subject_map[subject]
      issuers.append(cert)
      chain.remove(cert)

  assert len(chain) == 1

  while issuers:
    issuer = subject_map[chain[-1].getIssuer()]
    assert issuer
    chain.append(issuer)
    issuers.remove(issuer)

  return chain
