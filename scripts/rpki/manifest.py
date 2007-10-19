# $Id$

"""Signed manifests.  This is just the ASN.1 encoder, the rest is in
rpki.x509 with the rest of the DER_object code.

Note that rpki.x509.SignedManifest implements the signed manifest;
the structures here are just the payload of the CMS eContent field.
"""

from POW._der import *

class FileAndHash(Sequence):
  def __init__(self, optional=0, default=''):
    self.file = IA5String()
    self.hash = AltBitString()
    contents = [ self.file, self.hash ]
    Sequence.__init__(self, contents, optional, default)

class FilesAndHashes(SequenceOf):
  def __init__(self, optional=0, default=''):
    SequenceOf.__init__(self, FileAndHash, optional, default)

class Manifest(Sequence):
  def __init__(self, optional=0, default=''):
    self.version        = Integer()      
    self.explicitVersion = Explicit(CLASS_CONTEXT, FORM_CONSTRUCTED, 0, self.version, 0, 'oAMCAQA=')
    self.manifestNumber = Integer()
    self.thisUpdate     = GeneralizedTime()
    self.nextUpdate     = GeneralizedTime()
    self.fileHashAlg    = Oid()
    self.fileList       = FilesAndHashes()

    contents = [ self.explicitVersion,
                 self.manifestNumber,
                 self.thisUpdate,
                 self.nextUpdate,
                 self.fileHashAlg,
                 self.fileList ]
    Sequence.__init__(self, contents, optional, default)
