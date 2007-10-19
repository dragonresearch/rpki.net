# $Id$

"""Signed manifests.  This is just the ASN.1 encoder, the rest is in
rpki.x509 with the rest of the DER_object code.

Note that rpki.x509.SignedManifest inmplements the signed manifest;
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

    # I'm having trouble decoding the ASN.1 as currently specified.
    # I've asked about this on the mailing list, but I see three
    # options:
    #
    # 1) What the spec currently says, which doesn't quite work.
    #
    # 2) Get rid of the default on the version field, which might
    #    make sense as it doesn't waste a lot of space.
    #
    # 3) Explictly tag the version field, which seems to be the usual
    #    ASN.1 thing to do in these situations.
    #
    # Until the mailing list settles this, I've included code for all
    # three options here, using the numbers above.
    #
    # Clean all this up once the mailing list settles it.

    which_option = 3

    if which_option == 1:
      self.version      = Integer(0, "AgEA")

    if which_option in (2, 3):
      self.version      = Integer()      

    if which_option == 3:
      self.explicitVersion = Explicit(CLASS_CONTEXT, FORM_CONSTRUCTED, 0, self.version, 0, 'oAMCAQA=')

    self.manifestNumber = Integer()
    self.thisUpdate     = GeneralizedTime()
    self.nextUpdate     = GeneralizedTime()
    self.fileHashAlg    = Oid()
    self.fileList       = FilesAndHashes()

    if which_option in (1, 2):
      contents = [ self.version ]
    else:
      contents = [ self.explicitVersion ]

    contents += [
                 self.manifestNumber,
                 self.thisUpdate,
                 self.nextUpdate,
                 self.fileHashAlg,
                 self.fileList ]
    Sequence.__init__(self, contents, optional, default)
