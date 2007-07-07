#*****************************************************************************#
#*                                                                           *#
#*  Copyright (c) 2002, Peter Shannon                                        *#
#*  All rights reserved.                                                     *#
#*                                                                           *#
#*  Redistribution and use in source and binary forms, with or without       *#
#*  modification, are permitted provided that the following conditions       *#
#*  are met:                                                                 *#
#*                                                                           *#
#*      * Redistributions of source code must retain the above               *#
#*        copyright notice, this list of conditions and the following        *#
#*        disclaimer.                                                        *#
#*                                                                           *#
#*      * Redistributions in binary form must reproduce the above            *#
#*        copyright notice, this list of conditions and the following        *#
#*        disclaimer in the documentation and/or other materials             *#
#*        provided with the distribution.                                    *#
#*                                                                           *#
#*      * The name of the contributors may be used to endorse or promote     *#
#*        products derived from this software without specific prior         *#
#*        written permission.                                                *#
#*                                                                           *#
#*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS      *#
#*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT        *#
#*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS        *#
#*  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS   *#
#*  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,          *#
#*  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT         *#
#*  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,    *#
#*  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    *#
#*  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      *#
#*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE    *#
#*  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.     *#
#*                                                                           *#
#*****************************************************************************#

import exceptions, types, copy, string, time, base64, traceback, cStringIO

DEBUG = 0

# CLASS
CLASS_UNIVERSAL   = 0x00
CLASS_APPLICATION = 0x40
CLASS_CONTEXT     = 0x80
CLASS_PRIVATE     = 0xC0

# FORM
FORM_PRIMITIVE	   = 0x00
FORM_CONSTRUCTED	= 0x20

# TAG
TAG_BOOLEAN          = 0x01
TAG_INTEGER          = 0x02
TAG_BITSTRING        = 0x03
TAG_OCTETSTRING      = 0x04
TAG_NULL             = 0x05
TAG_OID              = 0x06
TAG_OBJDESCRIPTOR    = 0x07
TAG_EXTERNAL         = 0x08
TAG_REAL             = 0x09
TAG_ENUMERATED       = 0x0A
TAG_EMBEDDED_PDV     = 0x0B
TAG_UTF8STRING       = 0x0C
TAG_SEQUENCE         = 0x10
TAG_SET              = 0x11
TAG_NUMERICSTRING    = 0x12
TAG_PRINTABLESTRING  = 0x13
TAG_T61STRING        = 0x14
TAG_VIDEOTEXSTRING   = 0x15
TAG_IA5STRING        = 0x16
TAG_UTCTIME          = 0x17
TAG_GENERALIZEDTIME  = 0x18
TAG_GRAPHICSTRING    = 0x19
TAG_VISIBLESTRING    = 0x1A
TAG_GENERALSTRING    = 0x1B
TAG_UNIVERSALSTRING  = 0x1C
TAG_BMPSTRING        = 0x1E

_fragments = []

def _docset():
   return _fragments

def _addFragment(frag):
   global _fragments
   _fragments.append(frag)


_addFragment('''
<moduleDescription>
   <header>
      <name>POW.pkix</name>
      <author>Peter Shannon</author>
   </header>
   <body>
      <para>
         This module is a solution to reading and writing X509v3 written
         purely in Python.  It does use limited facilities from POW for
         signing and verifying but these could be replaced easily.  It is
         an abstract module and to use it successfully RFC3280 should be
         referred to as well as the sourcecode where necessary.  The correct
         use of many extensions often not clear from the definitions alone.
         Do refer to the RFC for details.
      </para>
      <para>
         Each constructed objects defined in the RFC is built from primitives
         defined by the ASN1 recommedations.  Not all ASN1 primitive are available but all those
         required for X509v3 should be.  The implementation is more or less
         complete for DER encoding the only caveat, aside from a few
         missing objects, is the behaviour of <classname>SET</classname> objects
         and <classname>SET OF</classname> objects.  The order the objects are
         written in should be determined at runtime by sorting their tags but this
         library does not do this.  For X509 it isn't really necessary
         since all the <classname>Set</classname> objects are simple and the
         order they are written in is defined by the object's constructor.
      </para>
      <para>
         Every documented object in this module supports the functions documented for
         <classname>_GeneralObject</classname>.  In general the function
         will only be documented in descendant classes if the class changes
         the behaviour significantly from its ancestor.  This would
         normally be <classname>_GeneralObject</classname> or
         <classname>Sequence</classname>.
      </para>
   </body>
</moduleDescription>
''')

class DerError(Exception):
   def __init__(self, msg):
      if not isinstance(msg, types.StringType):
         raise Exception, 'argunment should be a string'
      self.msg = msg

   def __repr__(self):
         return self.msg

   __str__ = __repr__

class _Tag(object):
   def __init__(self):
      self.tagclass = 0
      self.tagform = 0
      self.tagnumber = 0

   def __repr__(self):
      return '(%s, %s, %s)' % (self.tagclass, self.tagform, self.tagnumber)

   def write(self, file):
      if self.tagnumber < 31:
         file.write( chr(self.tagclass | self.tagform | self.tagnumber) )
      else:
         val = copy.deepcopy(self.tagnumber)
         bytes = []
         while val:
            byte = val & 0x7F
            bytes.append(byte | 0x80)
            val = val >> 7
         bytes[0] = bytes[0] ^ 0x80
         bytes.append( self.tagclass | self.tagform | 0x1F )
         bytes.reverse()
         file.write( string.join(map(chr, bytes), '') )

   def read(self, file):
      octet1 = ord( file.read(1) )
      self.tagclass = octet1 & 0xC0
      self.tagform = octet1 & 0x20
      value = octet1 & 0x1F
      if value < 31:
         self.tagnumber = value
      else:
         total = 0
         byte = 0x80
         while byte & 0x80:
            byte = ord( file.read(1) )
            if byte & 0x80:
               total = (total << 7) | byte ^ 0x80
            else:
               total = (total << 7) | byte
         self.tagnumber = total
 
class _Length(object):
   def __init__(self):
      self.length = 0

   def __repr__(self):
      return '(%s)' % self.length

   def write(self, file):
      if self.length < 128:
         file.write( chr(self.length) )
      else:
         val = copy.deepcopy(self.length)
         bytes = []
         while val:
            byte = val & 0xFF
            bytes.append(byte)
            val = val >> 8
         lengthOfLength = len(bytes)
         if lengthOfLength > 126:
            raise DerError, 'object is too long!'
         bytes.append(lengthOfLength)  
         bytes.reverse()
         bytes[0] = bytes[0] ^ 0x80
         file.write( string.join(map(chr, bytes), '') )

   def read(self, file):
      octet1 = ord( file.read(1) )
      if octet1 < 128:
         self.length = octet1
      else:
         total = 0
         byte = 0
         for i in range(octet1 ^ 0x80):
            byte = ord( file.read(1) )
            total = (total << 8) | byte
         self.length = total
 
class _TlvIo(_Tag, _Length):
   def __init__(self, file):
      self.file = file
      self.offset = None
      self.valueOffset = None

   def __repr__(self):
      return '<TAG:%s Length:%s>' % (_Tag.__repr__(self), _Length.__repr__(self))

   def __nonzero__(self):
      pos = self.file.tell()
      self.file.seek(0,2)
      if self.file.tell():
         self.file.seek(pos)
         return 1
      else:
         return 0

   def read(self):
      self.offset = self.file.tell()
      _Tag.read( self, self.file )
      _Length.read( self, self.file )
      self.valueOffset = self.file.tell()
      self.file.seek( self.length, 1 )

   def readValue(self):
      self.file.seek( self.valueOffset )
      return self.file.read( self.length )

   def write(self, val):
      _Tag.write( self, self.file )
      self.length = len(val)
      _Length.write( self, self.file )
      self.file.write(val)

def _decodeBoolean(val):
   'der encoded value not including tag or length'
   if not isinstance(val, types.StringType):
      raise DerError, 'argument should be a string'
   if ord(val) == 0xFF:
      return 1
   elif ord(val) == 0x00:
      return 0
   else:
      raise DerError, 'boolean should be encode as all 1s or all 0s'

def _encodeBoolean(val):
   'anything we can test for truth'
   if val:
      return chr(0xFF)
   else:
      return chr(0x00)

def _decodeInteger(val):
   'der encoded value not including tag or length'
   if not isinstance(val, types.StringType):
      raise DerError, 'argument should be a string'
   total = 0
   if ord(val[0]) & 0x80:
      val = map( lambda x : ord(x) ^ 0xFF, val )
      for byte in val:
         total = (total << 8) | byte
      total = -(total+1) 
   else:
      for byte in val:
         total = (total << 8) | ord(byte)
   return total

def _encodeInteger(val):
   'python integer'
   if not isinstance(val, types.IntType):
      raise DerError, 'argument should be an integer'
   if val == 0:
      return chr(0x00)
   else:
      val2 = copy.deepcopy(val)
      if val2 < 0:
         val2 = -(val2+1)
      bytes = []
      byte = 0
      while val2:
         byte = val2 & 0xFF
         bytes.append(byte)
         val2 = val2 >> 8
      # if we have no used up the last byte to represent the value we need
      # to add one more on to show if this is negative of positive.  Also,
      # due to adding 1 and inverting -1 would be 0 or if 0 is the encoding
      # value, so bytes would empty and this would lead to and empty value
      # and this would not be working properly.  Adding this null byte
      # fixes this, since it is inverted to -1 and preserved for 0.
      if byte & 0x80 or not bytes:
         bytes.append(0x00)
      if val < 0:
         bytes = map( lambda x : x ^ 0xFF, bytes )
      bytes.reverse()

      return string.join(map(chr, bytes), '')

def _decodeBitString(val):
   'der encoded value not including tag or length'
   if not isinstance(val, types.StringType):
      raise DerError, 'argument should be a string'
   bitmasks = [0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01]
   unused = ord( val[0] )
   bits = []
   for byte in val[1:]:
      for j in range(8):
         if ord(byte) & bitmasks[j]:
            bits.append(1)
         else:
            bits.append(0)
   if unused == 0:
      return tuple(bits)
   else:
      return tuple(bits[:-unused])
 
def _encodeBitString(val):
   'list of true/false objects ie [0,1,1,0,1,1]'
   if not (isinstance(val, types.ListType) or isinstance(val, types.TupleType)):
      raise DerError, 'argument should be a list or tuple'
   bitmasks = [0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01]
   bytes = []
   fits, leftover = divmod(len(val), 8)
   nobytes = fits
   if leftover > 0:
      nobytes = nobytes + 1
   if leftover:
      unused = 8 - leftover 
   else:
      unused = 0
   bytes.append(unused)
   for i in range(nobytes):
      byte = 0
      for j in range(8):
         offset = j + i*8
         if offset < len(val):
            if val[offset]:
               byte = byte | bitmasks[j]
      bytes.append(byte)

   return string.join(map(chr, bytes), '')

def _decodeOid(val):
   'der encoded value not including tag or length'
   if not isinstance(val, types.StringType):
      raise DerError, 'argument should be a string'
   arc12 = ord( val[0] )
   arc1, arc2 = divmod(arc12, 40)
   oids = [arc1,arc2]

   total = 0
   for byte in val[1:]:
      val = ord(byte)
      if val & 0x80:
         total = (total << 7) | (val ^ 0x80)
      else:
         total = (total << 7) | val
         oids.append(total)
         total = 0
      
   return tuple(oids)

def _encodeOid(val):
   'list of intgers'
   if not (isinstance(val, types.ListType) or isinstance(val, types.TupleType)):
      raise DerError, 'argument should be a list or tuple'
   oids = []
   oids.append( chr(40 * val[0] + val[1]) ) 
   for val in val[2:]:
      if val == 0:
         oids.append( chr(0) )
      else:
         bytes = []
         while val:
            val, rem = divmod(val, 128)
            bytes.append(rem | 0x80)
         bytes[0] = bytes[0] ^ 0x80
         bytes.reverse()
         oids.append( string.join(map(chr, bytes), '') )

   return string.join(oids, '')

def _decodeSequence(val):
   'der encoded value not including tag or length'
   if not isinstance(val, types.StringType):
      raise DerError, 'argument should be a string'
   buf = cStringIO.StringIO(val)
   buflen = len(val)
   tvls = []
   while buf.tell() < buflen:
      t = _TlvIo(buf)
      t.read()
      tvls.append(t)
   return tuple(tvls)

def _encodeSequence(val):
   'list of GenerlObjects'
   if not (isinstance(val, types.ListType) or isinstance(val, types.TupleType)):
      raise DerError, 'argument should be a list or tuple'
   buf = cStringIO.StringIO()
   for obj in val:
      if obj:
         obj.write(buf)
      elif not obj.optional:
         raise DerError, 'object not set which should be: %s' % obj
         
   return buf.getvalue()

_addFragment('''
<class>
   <header>
      <name>_GeneralObject</name>
   </header>
   <body>
      <para>
         <classname>_GeneralObject</classname> is the basis for all DER objects,
         primitive or constructed.  It defines the basic behaviour of an
         object which is serialised using the tag, length and value
         approach of DER.  It is unlikely you would ever want to
         instantiate one of these directly but I include a description
         since many primatives don't override much of
         <classname>_GeneralObject</classname>'s functions. 
      </para>
   </body>
</class>
''')

class _GeneralObject(object):

   _addFragment('''
   <constructor>
      <header>
         <memberof>_GeneralObject</memberof>
         <parameter>normclass</parameter>
         <parameter>normform</parameter>
         <parameter>normnumber</parameter>
         <parameter>encRoutine</parameter>
         <parameter>decRoutine</parameter>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
      <body>
         <para>
            <parameter>normclass</parameter> is the class of the object,
            ei: universal, application, context or private.
            <parameter>normform</parameter> is the form of the object, ei
            primitive or constructed.  <parameter>normnumber</parameter> is
            the tag number of the object.
            <parameter>encRoutine</parameter> is a function which takes a
            value and encodes it according the appropriate DER rules.
            <parameter>decRoutine</parameter> is a function which reads a
            string value and returns a value which is more useful in
            Python.  <parameter>optional</parameter> is a boolean
            indicating if this object is optional.  The final parameter,
            <parameter>default</parameter> is the base 64 encoded DER
            value, which should be used as the default in leu of a value to
            read or incase it is unset.
         </para>
      </body>
   </constructor>
   ''')

   def __init__(self, normclass, normform, normnumber, encRoutine, decRoutine, optional=0, default=''):
      if not isinstance(normclass, types.IntType):
         raise DerError, 'nomrclass argument should be an integer : %s' % normclass
      if not isinstance(normform, types.IntType):
         raise DerError, 'normform argument should be an integer : %s' % normform
      if not isinstance(normnumber, types.IntType):
         raise DerError, 'normnumber argument should be an integer : %s' % normnumber
      if not isinstance(encRoutine, types.FunctionType):
         raise DerError, 'encRoutine argument should be an function : %s' % encRoutine
      if not isinstance(decRoutine, types.FunctionType):
         raise DerError, 'decRoutine argument should be an function : %s' % decRoutine 
      if not isinstance(optional, types.IntType):
         raise DerError, 'optional argument should be an integer : %s' % optional
      if not isinstance(default, types.StringType):
         raise DerError, 'default argument should be an String : %s' % default
      self.normclass = normclass
      self.normform = normform
      self.normnumber = normnumber
      self.encRoutine = encRoutine
      self.decRoutine = decRoutine
      self.value = None
      self.optional = optional
      self.default = default
      self.reset()

   def _ioSafe(self):
      'is it safe to write this object'
      if self.optional or self._isSet():
         return 1
      else:
         return 0

   def _isSet(self):
      'are the values of this object set or not'
      if self.value != None:
         return 1
      else:
         return 0

   _addFragment('''
   <method>
      <header>
         <memberof>_GeneralObject</memberof>
         <name>reset</name>
      </header>
      <body>
         <para>
            This function re-initialises the object, clearing the value or
            setting it to any default.
         </para>
      </body>
   </method>
   ''')
   def reset(self):
      self.value = None
      if self.default:
         buf = cStringIO.StringIO( base64.decodestring( self.default ) )
         io = _TlvIo(buf)
         io.read()
         self.read(io)

   _addFragment('''
   <method>
      <header>
         <memberof>_GeneralObject</memberof>
         <name>set</name>
         <parameter>value</parameter>
      </header>
      <body>
         <para>
            This dosn't do much except store <parameter>value</parameter>,
            presumably prior to writing the object.  The correct values to
            use would be determined by the encoder or decoder this class is
            instantiated with.  Be careful, there is some flexibility in
            setting objects so you might find that once the object has been
            written and read back in the value isn't identical.  A good
            example would be anything which contains a sequence(list or
            tuple), all sequence objects are returned as tuples.
         </para>
      </body>
   </method>
   ''')
   def set(self, value):
      if value != None:
         self.value = value

   _addFragment('''
   <method>
      <header>
         <memberof>_GeneralObject</memberof>
         <name>get</name>
      </header>
      <body>
         <para>
            Gets the value stored presumably after reading the object.
         </para>
      </body>
   </method>
   ''')
   def get(self):
      return self.value

   _addFragment('''
   <method>
      <header>
         <memberof>_GeneralObject</memberof>
         <name>implied</name>
         <parameter>impclass</parameter>
         <parameter>impform</parameter>
         <parameter>impnumber</parameter>
      </header>
      <body>
         <para>
            This function is used to change how the tag is written or read
            for a particular object and should be called in the constructor
            for derived objects.  If you have an example of the structure you need to
            process, Pete Gutmann's excellent
            <application>dumpasn1</application> can be invaluable for
            debugging objects.
         </para>
      </body>
   </method>
   ''')
   def implied(self, impclass, impform, impnumber):
      if not isinstance(impclass, types.IntType):
         raise DerError, 'impclass argument should be an integer'
      if not isinstance(impform, types.IntType):
         raise DerError, 'impform argument should be an integer'
      if not isinstance(impnumber, types.IntType):
         raise DerError, 'impnumber argument should be an integer'
      self.normclass = impclass
      self.normform = impform
      self.normnumber = impnumber

   _addFragment('''
   <method>
      <header>
         <memberof>_GeneralObject</memberof>
         <name>read</name>
         <parameter>io</parameter>
      </header>
      <body>
         <para>
            <parameter>io</parameter> should be a file like object.  If the
            object being read matches the expected class, form and tag the
            value is read and decoded using
            <function>decRoutine</function>.  Else, if it has a default
            that is read and stored.  
         </para>
         <para>
            The return value of this function does not indicate success but
            whether this TLV was processed successfully.  This bahaviour is
            vital for processing constructed types since the object may be
            optional or have a default.  Failure to decode would be indicated 
            by an exception.  
         </para>
      </body>
   </method>
   ''')

   def read(self, io=None):    

      processDefOpt = 0
      if io == None:
         processDefOpt = 1
      elif isinstance(io, _TlvIo):
         if not io:
            processDefOpt = 1
      else:
         pos = io.tell()
         io.seek(0,2)
         if io.tell():
            io.seek(pos)
         else:
            processDefOpt = 1

      if processDefOpt:
         if self.optional or self.default:
            self.reset()
            return 0
         else:
            raise DerError, 'no TLV is available to read in non-optional/non-default object: %s' % repr(self)

      if not isinstance(io, _TlvIo):
         tmp = _TlvIo(io)
         tmp.read()
         io = tmp

      if io.tagclass != self.normclass or io.tagform != self.normform or io.tagnumber != self.normnumber:
         if self.default or self.optional:
            self.reset()
            return 0
         else:
            raise DerError, 'error in encoding, missing object:%s' % repr(self)
      else:
         derval = io.readValue()
         self.value = self.decRoutine( derval )
         return 1

   _addFragment('''
   <method>
      <header>
         <memberof>_GeneralObject</memberof>
         <name>write</name>
         <parameter>io</parameter>
      </header>
      <body>
         <para>
            If this object has not been set and is not optional and dosn't
            have a default, a <classname>DerError</classname> exception will be raised
         </para>
         <para>
            If no value has been set and this object is optional, nothing
            is written.  If this object's value is equal to the default,
            nothing is written as stipulated by DER.  Otherwise the value
            is encoded and written.  
         </para>
      </body>
   </method>
   ''')

   def write(self, file):
      if not self._ioSafe():
         raise DerError, 'object not set which must be: %s' % repr(self)
      elif self.optional and self.value == None:
         pass
      else:
         buf = cStringIO.StringIO()
         io = _TlvIo(buf)
         io.tagclass = self.normclass
         io.tagform = self.normform
         io.tagnumber = self.normnumber
         derval = self.encRoutine( self.value )
         io.length = len(derval)
         io.write(derval)
         if self.default:
            if buf.getvalue() != base64.decodestring(self.default):
               file.write( buf.getvalue() )
         else:
            file.write( buf.getvalue() )

   _addFragment('''
   <method>
      <header>
         <memberof>_GeneralObject</memberof>
         <name>toString</name>
      </header>
      <body>
         <para>
            Encodes the value in DER and returns it as a string.
         </para>
      </body>
   </method>
   ''')

   def toString(self):
      buf = cStringIO.StringIO()
      self.write(buf)
      return buf.getvalue()

   _addFragment('''
   <method>
      <header>
         <memberof>_GeneralObject</memberof>
         <name>fromString</name>
      </header>
      <body>
         <para>
            Decodes the string and sets the value of this object.
         </para>
      </body>
   </method>
   ''')

   def fromString(self, value):
      buf = cStringIO.StringIO(value)
      self.read(buf)

class Any(_GeneralObject):

   def __init__(self):
      self.value = None
      self.normclass = None
      self.normform = None
      self.normnumber = None

   def _ioSafe(self):
      if self.optional or (self._isSet() and self.normclass != None and self.normform != None and self.normnumber != None):
         return 1
      else:
         return 0

   def setTag(self, klass, form, number):
      self.normclass = klass
      self.normform = form
      self.normnumber = number

   def reset(self):
      self.value = None

   def get(self):
      return self.value

   def set(self, value):
      self.value = value

   def write(self,file):
      if not self._ioSafe():
         raise DerError, 'object not set which must be: %s' % repr(self)
      elif self.optional and self.value == None:
         pass
      else:
         buf = cStringIO.StringIO()
         io = _TlvIo(buf)
         io.tagclass = self.normclass
         io.tagform = self.normform
         io.tagnumber = self.normnumber
         io.length = len(self.value)
         io.write(self.value)
         file.write(buf.getvalue())

   def read(self, io=None):    

      processDefOpt = 0
      if io == None:
         processDefOpt = 1
      elif isinstance(io, _TlvIo):
         if not io:
            processDefOpt = 1
      else:
         pos = io.tell()
         io.seek(0,2)
         if io.tell():
            io.seek(pos)
         else:
            processDefOpt = 1
      if processDefOpt:
         if self.optional or self.default:
            self.reset()
            return 0
         else:
            raise DerError, 'no TLV is available to read in non-optional/non-default object: %s' % repr(self)

      if not isinstance(io, _TlvIo):
         tmp = _TlvIo(io)
         tmp.read()
         io = tmp

      self.value = io.readValue()
      self.normclass = io.tagclass
      self.normform = io.tagform
      self.normnumber = io.tagnumber

_addFragment('''
<class>
   <header>
      <name>Boolean</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 BOOLEAN type.  It can be set
         with any object which can be tested for truth. 
      </para>
   </body>
</class>
''')

class Boolean(_GeneralObject):                            # 0x01

   _addFragment('''
   <constructor>
      <header>
         <memberof>Boolean</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')
   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_BOOLEAN, _encodeBoolean, _decodeBoolean, optional, default)

_addFragment('''
<class>
   <header>
      <name>Integer</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 INTEGER type.  It should be set
         with a Python integer.
      </para>
   </body>
</class>
''')

class Integer(_GeneralObject):                            # 0x02

   _addFragment('''
   <constructor>
      <header>
         <memberof>Integer</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')
   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_INTEGER, _encodeInteger, _decodeInteger, optional, default)

_addFragment('''
<class>
   <header>
      <name>BitString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 BIT STRING type.  It should be set
         with a sequence of integers.  A non-zero number will set the bit,
         zero will leave the bit unset.
      </para>
   </body>
</class>
''')

class BitString(_GeneralObject):                          # 0x03

   _addFragment('''
   <constructor>
      <header>
         <memberof>BitString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')
   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_BITSTRING, _encodeBitString, _decodeBitString, optional, default)

_addFragment('''
<class>
   <header>
      <name>AltBitString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 BIT STRING type.  It differs from
         the first <classname>BitString</classname> in that it's coding
         routines treat values as binary data and do not interpret the data
         in any way.  Some application treat the
         <classname>BIT STRING</classname> in the same way as
         <classname>OCTET STRING</classname> type, hence this extra object.
      </para>
   </body>
</class>
''')

class AltBitString(_GeneralObject):                       # 0x03

   _addFragment('''
   <constructor>
      <header>
         <memberof>AltBitString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_BITSTRING, lambda x : chr(0)+x, lambda x : x[1:], optional, default)

_addFragment('''
<class>
   <header>
      <name>OctetString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 OCTET STRING type.  This object
         can be set with any binary data.
      </para>
   </body>
</class>
''')
class OctetString(_GeneralObject):                        # 0x04

   _addFragment('''
   <constructor>
      <header>
         <memberof>OctetString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_OCTETSTRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>Null</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 NULL type.  There is no point in
         setting this object, the value will always be ignored when it is
         written out.
      </para>
   </body>
</class>
''')
class Null(_GeneralObject):                               # 0x05

   _addFragment('''
   <constructor>
      <header>
         <memberof>Null</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_NULL, lambda x : '', lambda x : '', optional, default)
      self.value = '' 

   def _ioSafe(self):
      return 1

   def reset(self):
      self.value =  ''

_addFragment('''
<class>
   <header>
      <name>Oid</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 OID type.  This object should be
         set with a list or tuple of integers defining an objects oid.
         Please note that the first three arcs have a restricted set of
         values, so encoding (5, 3, 7, 1) will produce bad results.
      </para>
   </body>
</class>
''')
class Oid(_GeneralObject):                                # 0x06

   _addFragment('''
   <constructor>
      <header>
         <memberof>Oid</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_OID, _encodeOid, _decodeOid, optional, default)

_addFragment('''
<class>
   <header>
      <name>Enum</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 ENUM type.  This should be set
         using a Python integer, the meaning should be described in the
         ASN1 document for the object you are encoding.
      </para>
   </body>
</class>
''')
class Enum(_GeneralObject):                               # 0x0A

   _addFragment('''
   <constructor>
      <header>
         <memberof>Enum</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_ENUMERATED, _encodeInteger, _decodeInteger, optional, default)

_addFragment('''
<class>
   <header>
      <name>Utf8String</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 UTF8String type.  This object
         should be set with a string.  It is up to the application to ensure
         it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class Utf8String(_GeneralObject):                         # 0x0C

   _addFragment('''
   <constructor>
      <header>
         <memberof>Utf8String</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_UTF8STRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>NumericString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 NumericString type.  This should
  object should be set with a string.  It is up to the application to ensure
  it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class NumericString(_GeneralObject):                      # 0x12

   _addFragment('''
   <constructor>
      <header>
         <memberof>NumericString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_NUMERICSTRING, lambda x : x, lambda x : x, optional, default)
_addFragment('''
<class>
   <header>
      <name>PrintableString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 PrintableString type.  This should
  object should be set with a string.  It is up to the application to ensure
  it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class PrintableString(_GeneralObject):                    # 0x13

   _addFragment('''
   <constructor>
      <header>
         <memberof>PrintableString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_PRINTABLESTRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>T61String</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 T61String type.  This object
         should be set with a string.  It is up to the application to ensure
         it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class T61String(_GeneralObject):                          # 0x14

   _addFragment('''
   <constructor>
      <header>
         <memberof>T61String</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_T61STRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>VideotexString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 VideotexString type.  This should
  object should be set with a string.  It is up to the application to ensure
  it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class VideotexString(_GeneralObject):                     # 0x15

   _addFragment('''
   <constructor>
      <header>
         <memberof>VideotexString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_VIDEOTEXSTRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>IA5String</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 IA5String type.  This object
         should be set with a string.  It is up to the application to ensure
         it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class IA5String(_GeneralObject):                          # 0x16

   _addFragment('''
   <constructor>
      <header>
         <memberof>IA5String</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_IA5STRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>UtcTime</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 UTCTime type.  This object should
         be set with a string of the general format YYMMDDhhmmssZ.  The
         helper functions <function>time2utc</function> and
         <function>utc2time</function> can be used to handle the conversion
         from an integer to a string and back.
      </para>
   </body>
</class>
''')
class UtcTime(_GeneralObject):                            # 0x17

   _addFragment('''
   <constructor>
      <header>
         <memberof>UtcTime</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_UTCTIME, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>GeneralizedTime</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 GeneralizedTime type.  This object should
         be set with a string of the general format YYYYMMDDhhmmssZ.  The
         helper functions <function>time2utc</function> and
         <function>utc2time</function> can be used to handle the conversion
         from an integer to a string and back.
      </para>
   </body>
</class>
''')
class GeneralizedTime(_GeneralObject):                    # 0x18

   _addFragment('''
   <constructor>
      <header>
         <memberof>GeneralizedTime</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')


   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_GENERALIZEDTIME, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>GraphicString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 GraphicString type.  This should
         object should be set with a string.  It is up to the application to
         ensure it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class GraphicString(_GeneralObject):                      # 0x19

   _addFragment('''
   <constructor>
      <header>
         <memberof>GraphicString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_GRAPHICSTRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>VisibleString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 VisibleString type.  This should
         object should be set with a string.  It is up to the application to
         ensure it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class VisibleString(_GeneralObject):                      # 0xC0
 
   _addFragment('''
   <constructor>
      <header>
         <memberof>VisibleString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_VISIBLESTRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>GeneralString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 GeneralString type.  This should
         object should be set with a string.  It is up to the application to
         ensure it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class GeneralString(_GeneralObject):                      # 0xC0

   _addFragment('''
   <constructor>
      <header>
         <memberof>GeneralString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_GENERALSTRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>UniversalString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 UniversalString type.  This should
         object should be set with a string.  It is up to the application to
         ensure it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class UniversalString(_GeneralObject):                    # 0xC0

   _addFragment('''
   <constructor>
      <header>
         <memberof>UniversalString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_UNIVERSALSTRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>BmpString</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 BMPString type.  This object
         should be set with a string.  It is up to the application to ensure
         it only contains valid characters for this type.
      </para>
   </body>
</class>
''')
class BmpString(_GeneralObject):                          # 0xC0
 
   _addFragment('''
   <constructor>
      <header>
         <memberof>BmpString</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')

   def __init__(self, optional=0, default=''):
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_PRIMITIVE, TAG_BMPSTRING, lambda x : x, lambda x : x, optional, default)

_addFragment('''
<class>
   <header>
      <name>Sequence</name>
      <super>_GeneralObject</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 SEQUENCE type.  
      </para>
   </body>
</class>
''')
class Sequence(_GeneralObject):                           # 0x10

   _addFragment('''
   <constructor>
      <header>
         <memberof>Sequence</memberof>
         <super>_GeneralObject</super>
         <parameter>contents</parameter>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
      <body>
         <para>
            The <parameter>contents</parameter> should be a list or tuple containing
            the contents of the sequence.
            Two important members are initialised this this constructor.
            First <constant>self.next</constant> this is used to keep track
            of which TLVs in this sequence has been read succesfully.  The second,
            <constant>self.contents</constant> should be set to the list of
            objects stored in this sequence.  Note that the order they are
            specified in is the order in which they are written or read.
         </para>
      </body>
   </constructor>
   ''')

   def __init__(self, contents, optional=0, default=''):
      self.contents = contents
      self.next = 0
      _GeneralObject.__init__(self, CLASS_UNIVERSAL, FORM_CONSTRUCTED, TAG_SEQUENCE, _encodeSequence, _decodeSequence, optional, default)

   def _childRead(self, obj):
      if self.next < len(self.value):
         if obj.read( self.value[self.next] ):
            self.next += 1
      else:
         obj.read()

   _addFragment('''
   <method>
      <header>
         <memberof>Sequence</memberof>
         <name>readContents</name>
         <parameter>io</parameter>
         <parameter>contents</parameter>
      </header>
      <body>
         <para>
            This function implements basic SEQUENCE like reading behaviour.
            It will attempt to read each of the objects in
            <parameter>contents</parameter> in turn from
            <parameter>io</parameter>.  It exists as a function, separate
            from <function>read</function> for the benefit of the SEQUENCE
            OF implementation.
         </para>
         <para>
            The TLV of this SEQUENCE is read and parsed into a list of
            TLVs, which are store in <constant>self.value</constant>, by
            <classname>_GeneralObject</classname>.<function>read</function>.
            Then <function>read</function> is called on each member to
            process each TLV in turn.  The next TLV is moved onto only when
            a member returns TRUE from the read call.
         </para>
      </body>
   </method>
   ''')

   def readContents(self, io, contents):    
      if _GeneralObject.read( self, io ):
         for item in contents:
            Sequence._childRead( self, item )
         return 1
      else:
         return 0

   _addFragment('''
   <method>
      <header>
         <memberof>Sequence</memberof>
         <name>read</name>
         <parameter>io</parameter>
      </header>
      <body>
         <para>
            Most of the logic for reading is implemented in <function>readContents</function>
            so it can be reused for <classname>SequenceOf</classname>'s
            <function>read</function> function.
         </para>
      </body>
   </method>
   ''')

   def read(self, io=None):    
      self.next = 0
      return self.readContents(io, self.contents)

   _addFragment('''
   <method>
      <header>
         <memberof>Sequence</memberof>
         <name>write</name>
         <parameter>file</parameter>
      </header>
      <body>
         <para>
            <constant>self.value</constant> is set to the contents of this
            SEQUENCE and then written by calling
            <classname>_GeneralObject</classname>.<function>write</function>
            whos encoder will call <function>write</function> of
            each element in the list of contents in turn.
         </para>
      </body>
   </method>
   ''')

   def write(self, file):
      if self._ioSafe(): 
         if self._isSet(): 
            _GeneralObject.set( self, self.contents )
            _GeneralObject.write( self, file )
      elif self.optional:
         pass
      else:
         prob = self.findUnset()
         raise DerError, '%s is not in a state which can be written, %s is unset' % (repr(self), repr(prob) )

   _addFragment('''
   <method>
      <header>
         <memberof>Sequence</memberof>
         <name>set</name>
         <parameter>values</parameter>
      </header>
      <body>
         <para>
            Accessing and setting values for ASN1 objects is a bit of a
            thorny issue.  The problem stems from the arbitrary complexity
            of the data and the possible levels of nesting, which in
            practice are used and are quite massive.  Designing a good general
            approach is a bit tricky, perhaps nearly
            impossible.  I choose to use a most compact
            form which is excellent for simple objects and is very concise.
         </para>
         <para>
            <parameter>value</parameter> should be a list or tuple of
            values.  Each element of the list (or tuple) will be used in
            turn to set a member.  Defaults can be specified by using the
            default value itself or <constant>None</constant>.  Hence, for
            SEQUENCES of SEQUENCES, SEQUENCES OF, SET and so on
            <parameter>values</parameter> should consist of nested lists or
            tuples.  Look at the ASN1 specs for that object to figure out
            exactly what these should look like.
         </para>
      </body>
   </method>
   ''')

   def set(self, values):
      if self.contents == None:
         raise DerError, 'the contents attribute should be set before using this object'
      if not( isinstance(values, types.ListType) or isinstance(values, types.TupleType) ):
         raise DerError, 'a sequence should be set with a list or tuple of values' 
      if len(values) != len(self.contents):
         raise DerError, 'wrong number of values have been supplied to set %s. Expecting %i, got %i' % \
                  (self.__class__.__name__, len(self.contents), len(values) )

      i = 0
      for val in values:
         self.contents[i].set(val) 
         i = i + 1

   _addFragment('''
   <method>
      <header>
         <memberof>Sequence</memberof>
         <name>get</name>
      </header>
      <body>
         <para>
            A tuple of the values of the contents of this sequence will be
            returned.  Hence, for SEQUENCES of SEQUENCES, SEQUENCES OF, SET
            and so on nested tuples will be returned.
            <function>get</function> always returns tuples even if a list
            was used to set and object.
         </para>
      </body>
   </method>
   ''')

   def get(self):
      if self.contents == None:
         return _GeneralObject.get(self)   
      else:
         results = []
         for obj in self.contents:
            results.append( obj.get() )
         return tuple(results)

   def reset(self):
      if self.contents == None:
         raise DerError, 'this object has no members to set'
      self.next = 0
      for obj in self.contents:
         obj.reset() # clear all child objects prior to possible setting
                     # via default
      _GeneralObject.reset(self)

   def _isSet(self):
      if self.contents == None:
         raise DerError, 'this object has no members to set'
      for obj in self.contents:
         if not obj._ioSafe():
            return 0
      return 1

   def findUnset(self):
      if self.contents == None:
         raise DerError, 'this object has no members to check'
      for obj in self.contents:
         if not obj._ioSafe():
            return obj

   def _ioSafe(self):
      if self.optional or self._isSet():
         return 1
      else:
         for obj in self.contents:
            if not obj._ioSafe():
               return 0
         return 1

_addFragment('''
<class>
   <header>
      <name>SequenceOf</name>
      <super>Sequence</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 SEQUENCE OF construct.  
      </para>
   </body>
</class>
''')           
class SequenceOf(Sequence):

   _addFragment('''
   <constructor>
      <header>
         <memberof>SequenceOf</memberof>
         <super>Sequence</super>
         <parameter>contains</parameter>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
      <body>
         <para>
            The <parameter>contains</parameter> should be the constructor
            for the objects which this SEQUENCE OF contains.
         </para>
      </body>
   </constructor>
   ''')

   def __init__(self, contains, optional=0, default=''):
      self.contains = contains
      self.sequenceOf = []
      Sequence.__init__(self, [], optional, default)

   def _ioSafe(self):
      return 1

   def reset(self):
      if self.contents == None:
         raise DerError, 'this object has no members to set'
      self.next = 0
      self.sequenceOf = []
      _GeneralObject.reset(self)

   def _isSet(self):
      if self.sequenceOf:
         for obj in self.contents:
            if not obj._ioSafe():
               return 0
         return 1
      else:
         return 0

   def set(self, values):
      if isinstance(values, types.NoneType):
         return
      objects = []
      for val in values:
         obj = self.contains()
         obj.set(val)
         objects.append(obj)
      self.sequenceOf = objects

   def get(self):
      results = []
      for obj in self.sequenceOf:
         results.append( obj.get() )
      return tuple(results)

   def read(self, io=None):    
      self.sequenceOf = []
      self.next = 0
      if _GeneralObject.read( self, io ):
         for tagio in _GeneralObject.get(self):
            value = self.contains()
            value.read(tagio)
            self.sequenceOf.append(value)
         return 1
      else:
         return 0

   def write(self, file):
      if not self._isSet() and self.optional: 
         pass
      else:
         _GeneralObject.set( self, self.sequenceOf )
         _GeneralObject.write( self, file )

_addFragment('''
<class>
   <header>
      <name>Set</name>
      <super>Sequence</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 Set type.  
      </para>
   </body>
</class>
''')
class Set(Sequence):                                     # 0x11
 
   _addFragment('''
   <constructor>
      <header>
         <memberof>Set</memberof>
         <super>Sequence</super>
         <parameter>contents</parameter>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
      <body>
         <para>
            The <parameter>contents</parameter> should be a list containing
            the contents of the sequence.
         </para>
      </body>
   </constructor>
   ''')

   def __init__(self, contents, optional=0, default=''):
      Sequence.__init__(self, contents, optional, default)
      self.normnumber = TAG_SET

_addFragment('''
<class>
   <header>
      <name>SetOf</name>
      <super>SequenceOf</super>
   </header>
   <body>
      <para>
         This object represents the ASN1 SET OF construct.  
      </para>
   </body>
</class>
''')
class SetOf(SequenceOf):

   _addFragment('''
   <constructor>
      <header>
         <memberof>SetOf</memberof>
         <super>SequenceOf</super>
         <parameter>contains</parameter>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
      <body>
         <para>
            The <parameter>contains</parameter> should be the constructor
            for the objects which this SET OF contains.
         </para>
      </body>
   </constructor>
   ''')

   def __init__(self, contains, optional=0, default=''):
      SequenceOf.__init__(self, contains, optional, default)
      self.normnumber = TAG_SET

_addFragment('''
<class>
   <header>
      <name>Explicit</name>
      <super>Sequence</super>
   </header>
   <body>
      <para>
         Explicit objects support the DER concept of explicit tagging.  In
         general they behave just like a SEQUENCE which must have only one
         element.  See below for other differences.
      </para>
   </body>
</class>
''')
class Explicit(Sequence):           

   _addFragment('''
   <constructor>
      <header>
         <memberof>Explicit</memberof>
         <super>Sequence</super>
         <parameter>expclass</parameter>
         <parameter>expform</parameter>
         <parameter>expnumber</parameter>
         <parameter>contents</parameter>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
      <body>
         <para>
            <parameter>expclass</parameter>,
            <parameter>expform</parameter>,
            <parameter>expnumber</parameter> should be as
            specified in the ASN1 documentation for this object.
            <parameter>contents</parameter> should be an object instance
            such as <classname>Integer</classname>,
            <classname>Oid</classname> or a derived object which supports
            the <classname>_GeneralObjec</classname> interface.
         </para>
      </body>
   </constructor>
   ''')

   def __init__(self, expclass, expform, expnumber, contents, optional=0, default=''):
      self.contents = [contents]
      self.next = 0
      _GeneralObject.__init__(self, expclass, expform, expnumber, _encodeSequence, _decodeSequence, optional, default)

   _addFragment('''
   <method>
      <header>
         <memberof>Explicit</memberof>
         <name>set</name>
         <parameter>value</parameter>
      </header>
      <body>
         <para>
            <parameter>value</parameter> is passed direct to
            <function>set</function> of the explicit object, so it should
            not be placed in a list or tuple(unless you are setting a constructed
            object).  
         </para>
      </body>
   </method>
   ''')
   def set(self, value):
      return Sequence.set(self, [value])

   _addFragment('''
   <method>
      <header>
         <memberof>Explicit</memberof>
         <name>get</name>
      </header>
      <body>
         <para>
            The value of explicit object is returned and not
            put in a tuple.   
         </para>
      </body>
   </method>
   ''')
   def get(self):
      return Sequence.get(self)[0]

_addFragment('''
<class>
   <header>
      <name>Choice</name>
   </header>
   <body>
      <para>
         This object represents the ASN1 Choice type.  
      </para>
   </body>
</class>
''')
class Choice(object):

   _addFragment('''
   <constructor>
      <header>
         <memberof>Choice</memberof>
         <parameter>choices</parameter>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
      <body>
         <para>
            <parameter>choices</parameter> should be a dictionary of 
            objects which support the <classname>_GeneralObject</classname>
            interface.  The key being the name of the choice specified in the
            ASN1 documentation.  <parameter>optional</parameter> is a boolean
            indicating if this object is optional.  The final parameter,
            <parameter>default</parameter> is the base 64 encoded DER
            value, which should be used as the default in leu of a value to
            read or incase it is unset.  If neither
            <parameter>optional</parameter> or
            <parameter>default</parameter> is not set then the first choice
            which is optional or has a default will be honored.
         </para>
      </body>
   </constructor>
   ''')

   def __init__(self, choices, optional=0, default=''):
      self.value = None
      self.choices = choices
      self.optional = optional
      self.default = default
      self.choice = None
      self.reset()

   def _ioSafe(self):
      if self.optional or self._isSet():
         return 1
      elif self.choice and self.choices[ self.choice ]._ioSafe():
         return 1
      else:
         return 0

   def _isSet(self):
      if self.choice and self.choices[self.choice]._isSet():
         return 1
      else:
         return 0

   _addFragment('''
   <method>
      <header>
         <memberof>Choice</memberof>
         <name>reset</name>
      </header>
      <body>
         <para>
            This function re-initialises the object, clearing the value or
            setting it to any default.
         </para>
      </body>
   </method>
   ''')
   def reset(self):
      self.value = None
      self.choice = None
      if self.default:
         buf = cStringIO.StringIO( base64.decodestring( self.default ) )
         io = _TlvIo(buf)
         io.read()
         self.read(io)
      else:
         for key in self.choices.keys():
            self.choices[key].reset()
            if self.choices[key]._ioSafe():
               self.choice = key
               break;
            

   _addFragment('''
   <method>
      <header>
         <memberof>Choice</memberof>
         <name>set</name>
         <parameter>value</parameter>
      </header>
      <body>
         <para>
            <parameter>value</parameter> should be a list or tuple with two
            elements. The first value should be the name of the choice to
            be set and the second the value to set it with.
         </para>
      </body>
   </method>
   ''')
   def set(self, val):
      if isinstance(val, types.NoneType):
         return
      if not (isinstance(val, types.ListType) or isinstance(val, types.TupleType)):
         raise DerError, 'argument should be a list or tuple'
      if not self.choices.has_key( val[0] ):
         raise DerError, 'unknown choice: %s' % val[0]
      self.choices[ val[0] ].set(val[1])
      self.choice = val[0]

   _addFragment('''
   <method>
      <header>
         <memberof>Choice</memberof>
         <name>get</name>
      </header>
      <body>
         <para>
            This function will return tuple with two elements. The first
            value will be the name of the choice which was set and the second
            the value it was set to.
         </para>
      </body>
   </method>
   ''')

   def get(self):
      if self._isSet():
         return (self.choice, self.choices[ self.choice ].get())
      else:
         return None

   _addFragment('''
   <method>
      <header>
         <memberof>Choice</memberof>
         <name>toString</name>
      </header>
      <body>
         <para>
            Encodes the value in DER and returns it as a string.
         </para>
      </body>
   </method>
   ''')

   def toString(self):
      buf = cStringIO.StringIO()
      self.write(buf)
      return buf.getvalue()

   _addFragment('''
   <method>
      <header>
         <memberof>Choice</memberof>
         <name>fromString</name>
      </header>
      <body>
         <para>
            Decodes the string and sets the value of this object.
         </para>
      </body>
   </method>
   ''')

   def fromString(self, value):
      buf = cStringIO.StringIO(value)
      self.read(buf)

   _addFragment('''
   <method>
      <header>
         <memberof>Choice</memberof>
         <name>read</name>
         <parameter>io</parameter>
      </header>
      <body>
         <para>
            <parameter>io</parameter> should be a file like object.  If the
            object being read matches the expected class, form and tag the
            value is read and decoded using
            <function>decRoutine</function>.  Else, if it has a default
            that is read and stored.  
         </para>
         <para>
            The return value of this function does not indicate success but
            whether this TLV was processed successfully.  This bahaviour is
            vital for processing constructed types since the object may be
            optional or have a default.  Failure to decode would be indicated 
            by an exception.  
         </para>
      </body>
   </method>
   ''')

   def _readChoices(self, io):
      for key in self.choices.keys():
         try:
            readindicator = self.choices[key].read(io)
            self.choice = key
            break;
         except DerError:
            if DEBUG:
               traceback.print_exc()
      return readindicator
 
   def read(self, io=None):    

      self.choice = None
      processDefOpt = 0
      readindicator = 0

      if io == None:
         processDefOpt = 1
      elif isinstance(io, _TlvIo):
         if not io:
            processDefOpt = 1
      else:
         pos = io.tell()
         io.seek(0,2)
         if io.tell():
            io.seek(pos)
         else:
            processDefOpt = 1

      if processDefOpt:
         if self.optional or self.default:
            self.reset()
            return 0
         else:
            readindicator = self._readChoices(io)
            for key in self.choices.keys():
               try:
                  readindicator = self.choices[key].read(io)
                  self.choice = key
                  break;
               except DerError:
                  if DEBUG:
                     traceback.print_exc()
            if not self._isSet():
               raise DerError, 'no TLV is available to read in non-optional/non-default object: %s' % repr(self)
            else:
               return readindicator

      if not isinstance(io, _TlvIo):
         tmp = _TlvIo(io)
         tmp.read()
         io = tmp

      for key in self.choices.keys():
         try:
            if self.choices[key].read(io):
               self.choice = key
               readindicator = 1
               break;
         except DerError:
            if DEBUG:
               traceback.print_exc()
 
      if not self._isSet():
         self.reset()
      else:
         return readindicator

   _addFragment('''
   <method>
      <header>
         <memberof>Choice</memberof>
         <name>write</name>
         <parameter>file</parameter>
      </header>
      <body>
         <para>
            If this object has not been set and is not optional and dosn't
            have a default, a <classname>DerError</classname> exception will be raised
         </para>
         <para>
            If no value has been set and this object is optional, nothing
            is written.  If this object's value is equal to the default,
            nothing is written as stipulated by DER.  Otherwise the value
            is encoded and written.  
         </para>
      </body>
   </method>
   ''')
   def write(self,file):
      if self.optional and not self.choice:
         pass
      elif not self.choice:
         raise DerError, 'choice not set'
      elif self.choice:
         if self.default:
            defval = base64.decodestring( self.default )
            if defval != self.choices[ self.choice ].toString():
               self.choices[ self.choice ].write(file)
         else:
            self.choices[ self.choice ].write(file)
      else:
         raise DerError, 'an internal error has occured: %s' % repr(self)


