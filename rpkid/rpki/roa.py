"""ROA (Route Origin Authorization).

At the moment this is just the ASN.1 encoder.

This corresponds to draft-ietf-sidr-roa-format, which is a work in
progress, so this may need updating later.

$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

draft-ietf-sidr-roa-format-02 2.1.3.2 specifies:

     RouteOriginAttestation ::= SEQUENCE { 
        version [0] INTEGER DEFAULT 0, 
        asID  ASID, 
        exactMatch BOOLEAN,
        ipAddrBlocks ROAIPAddrBlocks } 
    
     ASID ::= INTEGER 
      
     ROAIPAddrBlocks ::= SEQUENCE of ROAIPAddressFamily 
      
     ROAIPAddressFamily ::= SEQUENCE { 
        addressFamily OCTET STRING (SIZE (2..3)), 
        addresses SEQUENCE OF IPAddress } 
   
     IPAddress ::= BIT STRING 

... but we now implement the new format that will supposedly appear
in the upcoming draft-ietf-sidr-roa-format-03:

     RouteOriginAttestation ::= SEQUENCE {
        version [0] INTEGER DEFAULT 0,
        asID  ASID,
        ipAddrBlocks SEQUENCE OF ROAIPAddressFamily }

     ASID ::= INTEGER

     ROAIPAddressFamily ::= SEQUENCE {
        addressFamily OCTET STRING (SIZE (2..3)),
        addresses SEQUENCE OF ROAIPAddress }

     ROAIPAddress ::= {
        address IPAddress,
        maxLength INTEGER OPTIONAL }
   
     IPAddress ::= BIT STRING 
"""

from POW._der import *

class ROAIPAddress(Sequence):
  def __init__(self, optional=0, default=''):
    self.address = BitString()
    self.maxLength = Integer(1)
    contents = [ self.address, self.maxLength ]
    Sequence.__init__(self, contents, optional, default)

class ROAIPAddresses(SequenceOf):
  def __init__(self, optional=0, default=''):
    SequenceOf.__init__(self, ROAIPAddress, optional, default)

class ROAIPAddressFamily(Sequence):
  def __init__(self, optional=0, default=''):
    self.addressFamily = OctetString()
    self.addresses = ROAIPAddresses()
    contents = [ self.addressFamily, self.addresses ]
    Sequence.__init__(self, contents, optional, default)

class ROAIPAddressFamilies(SequenceOf):
  def __init__(self, optional=0, default=''):
    SequenceOf.__init__(self,  ROAIPAddressFamily, optional, default)
 
class RouteOriginAttestation(Sequence):
  def __init__(self, optional=0, default=''):
    self.version = Integer()
    self.explicitVersion = Explicit(CLASS_CONTEXT, FORM_CONSTRUCTED, 0, self.version, 0, 'oAMCAQA=')
    self.asID = Integer()
    self.ipAddrBlocks = ROAIPAddressFamilies()
    contents = [ self.explicitVersion, self.asID, self.ipAddrBlocks ]
    Sequence.__init__(self, contents, optional, default)
