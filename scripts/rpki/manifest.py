# $Id$

from POW._der import *

class FileAndHash(Sequence):
  def __init__(self, optional=0, default=''):
    self.file = IA5String()
    self.hash = BitString()
    contents = [ self.file, self.hash ]
    Sequence.__init__(self, contents, optional, default)

class FilesAndHashes(SequenceOf):
  def __init__(self, optional=0, default=''):
    SequenceOf.__init__(self, FileAndHash, optional, default)

class Manifest(Sequence):
  def __init__(self, optional=0, default=''):
    self.version        = Integer(0, '\x00')
    self.manifestNumber = Integer()
    self.thisUpdate     = GeneralizedTime()
    self.nextUpdate     = GeneralizedTime()
    self.fileHashAlg    = Oid()
    self.fileList       = FilesAndHashes()
    contents = [ self.version,
                 self.manifestNumber,
                 self.thisUpdate,
                 self.nextUpdate,
                 self.fileHashAlg,
                 self.fileList ]
    Sequence.__init__(self, contents, optional, default)
