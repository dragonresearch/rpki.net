# $Id$

from POW._der import *

# This corresponds to draft-ietf-sidr-roa-format-01, which is a work
# in progress, so this may need updating later.

class IPAddresses(SequenceOf):
  def __init__(self, optional=0, default=''):
    SequenceOf.__init__(self, BitString, optional, default)

class ROAIPAddressFamily(Sequence):
  def __init__(self, optional=0, default=''):
    self.addressFamily = OctetString()
    self.addresses = IPAddresses()
    contents = [ self.addressFamily, self.addresses ]
    Sequence.__init__(self, contents, optional, default)

class ROAIPAddrBlocks(SequenceOf):
  def __init__(self, optional=0, default=''):
    SequenceOf.__init__(self,  ROAIPAddressFamily, optional, default)
 
class RouteOriginAttestation(Sequence):
  def __init__(self, optional=0, default=''):
    self.version = Integer(0, chr(0x00))
    self.asID = Integer()
    self.exactMatch = Boolean()
    self.ipAddrBlocks = ROAIPAddrBlocks()
    contents = [ self.version, self.asID, self.exactMatch, self.ipAddrBlocks ]
    Sequence.__init__(self, contents, optional, default)
