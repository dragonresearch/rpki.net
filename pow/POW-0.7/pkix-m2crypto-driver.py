# $Id$

"""Crypto driver for POW.pkix using M2Crypto.

This driver is part of an attempt to salvage the (really nice)
POW.pkix code from the POW package.  I like POW well enough, but it's
old and missing some pieces and the Python world seems to have moved
to M2Crypto.  But M2Crypto has nothing like POW.pkix, so I whacked
together an interface to let POW.pkix run over other crypto packages.

This module is a driver for M2Crypto.
"""

# NB: Module names may change eventually

import POW.pkix

class M2CryptoCryptoDriver(POW.pkix.CryptoDriver):
  """Dispatcher for crypto calls using M2Crypto package."""

  def __init__(self):
    import M2Crypto
    self.driver2OID = {
      "md5"       :  (1, 2, 840, 113549, 1, 1, 4),    # md5WithRSAEncryption
      "sha1"      :  (1, 2, 840, 113549, 1, 1, 5),    # sha1withRSAEncryption
      "ripemd160" :  (1, 2, 840, 113549, 1, 1, 6),    # ripemd160WithRSAEncryption
      "sha256"    :  (1, 2, 840, 113549, 1, 1, 11),   # sha256WithRSAEncryption
      }
    self.OID2driver = dict((v,k) for k,v in self.driver2OID.iteritems())

  def sign(self, key, oid, plaintext):
    digest = M2Crypto.EVP.MessageDigest(self.OID2driver[oid])
    digest.update(plaintext)
    return key.sign(digest.final(), self.OID2driver[oid])

  def verify(self, key, oid, plaintext, signature):
    return key.verify(plaintext, signature, self.OID2driver[oid])

  def keyDER(self, key):
    bio = M2Crypto.BIO.MemoryBuffer()
    key.save_key_der_bio(bio)
    return bio.read()
