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

import types, time, pprint, cStringIO, _der
from _simpledb import OidData as _OidData 
from _der import *

DEBUG = 0

_oidData = _OidData()
obj2oid = _oidData.obj2oid
oid2obj = _oidData.oid2obj

_fragments = []

def _docset():
   return _der._docset() + _fragments

#---------- crypto driver ----------#

class CryptoDriver(object):
   """Dispatcher for crypto calls.

   This module has very minimal dependencies on crypto code, as it's
   almost entirely about ASN.1 encoding and decoding.  Rather than
   wiring in the handful of crypto calls, we dispatch them through
   this driver.  The default driver uses POW, but you can replace it
   with any crypto package you like.

   This is a virtual class.  You will have to subtype it.
   """

   def getOID(self, digestType):
      """Convert a digest identifier into an OID.

      If the identifier we get is a tuple, we assume it's already an
      OID and just return it.  If the identifier is in the driver
      identifier mapping table, we use that to return an OID.
      Otherwise, we try mapping it via the name-to-OID database.
      """
      if isinstance(digestType, tuple):
         return digestType
      if digestType in self.driver2OID:
         return self.driver2OID[digestType]
      return obj2oid(digestType)
         
   def sign(self, key, oid, plaintext):
      """Sign something with an RSA key and a given digest algorithm."""
      raise NotImplementedError

   def verify(self, key, oid, plaintext, signature):
      """Verify a signature."""
      raise NotImplementedError

   def toPublicDER(self, key):
      """Get the DER representation of an RSA key."""
      raise NotImplementedError

   def fromPublicDER(self, der):
      """Set the driver representation of an RSA key from DER."""
      raise NotImplementedError

class POWCryptoDriver(CryptoDriver):
   """Dispatcher for crypto calls using POW package."""

   def __init__(self):
      global POW
      import POW
      self.driver2OID = {
         POW.MD2_DIGEST       :  (1, 2, 840, 113549, 1, 1, 2),    # md2WithRSAEncryption
         POW.MD5_DIGEST       :  (1, 2, 840, 113549, 1, 1, 4),    # md5WithRSAEncryption
         POW.SHA_DIGEST       :  (1, 3, 14, 3, 2, 15),            # shaWithRSAEncryption
         POW.SHA1_DIGEST      :  (1, 2, 840, 113549, 1, 1, 5),    # sha1withRSAEncryption
         POW.RIPEMD160_DIGEST :  (1, 2, 840, 113549, 1, 1, 6),    # ripemd160WithRSAEncryption
         POW.SHA256_DIGEST    :  (1, 2, 840, 113549, 1, 1, 11),   # sha256WithRSAEncryption
         POW.SHA384_DIGEST    :  (1, 2, 840, 113549, 1, 1, 12),   # sha384WithRSAEncryption
         POW.SHA512_DIGEST    :  (1, 2, 840, 113549, 1, 1, 13),   # sha512WithRSAEncryption
         }
      self.OID2driver = dict((v,k) for k,v in self.driver2OID.items())
         
   def _digest(self, oid, plaintext):
      digest = POW.Digest(self.OID2driver[oid])
      digest.update(plaintext)
      return digest.digest()

   def sign(self, key, oid, plaintext):
      return key.sign(self._digest(oid, plaintext), self.OID2driver[oid])

   def verify(self, key, oid, plaintext, signature):
      return key.verify(signature, self._digest(oid, plaintext), self.OID2driver[oid])

   def toPublicDER(self, key):
      return key.derWrite(POW.RSA_PUBLIC_KEY)

   def fromPublicDER(self, der):
      return POW.derRead(POW.RSA_PUBLIC_KEY, der)

_cryptoDriver = None                    # Don't touch this directly

def setCryptoDriver(driver):
   """Set crypto driver.

   The driver should be an instance of CryptoDriver.
   """
   assert isinstance(driver, CryptoDriver)
   global _cryptoDriver
   _cryptoDriver = driver

def getCryptoDriver():
   """Return the currently selected CryptoDriver instance.

   If no driver has been selected, instantiate the default POW driver.
   """
   global _cryptoDriver
   if _cryptoDriver is None:
      setCryptoDriver(POWCryptoDriver())
   return _cryptoDriver

#---------- crypto driver ----------#

def _addFragment(frag):
   global _fragments
   _fragments.append(frag)

_addFragment('''
<modulefunction>
   <header>
      <name>utc2time</name>
      <parameter>time</parameter>
   </header>
   <body>
      <para>
         This is a helper function for turning a UTCTime string into an
         integer.  It isn't built into the encoder since the various
         functions which are used to manipulate the tm structure are
         notoriously unreliable.
      </para>
   </body>
</modulefunction>
''')
def utc2time(val):
   'der encoded value not including tag or length'
   if not isinstance(val, types.StringType):
      raise DerError, 'argument should be a string'
   t = time.strptime(val, '%y%m%d%H%M%SZ')
   return int(time.mktime(t))

_addFragment('''
<modulefunction>
   <header>
      <name>time2utc</name>
      <parameter>time</parameter>
   </header>
   <body>
      <para>
         This is a helper function for turning an integer into a
         UTCTime string.  It isn't built into the encoder since the
         various functions which are used to manipulate the tm structure
         are notoriously unreliable.
      </para>
   </body>
</modulefunction>
''')
def time2utc(val):
   'numerical time value like time_t'
   val = int(val)
   t = time.gmtime(val)
   return time.strftime('%y%m%d%H%M%SZ', t)

_addFragment('''
<modulefunction>
   <header>
      <name>gen2time</name>
      <parameter>time</parameter>
   </header>
   <body>
      <para>
         This is a helper function for turning a GeneralizedTime string into an
         integer.  It isn't built into the encoder since the various
         functions which are used to manipulate the tm structure are
         notoriously unreliable.
      </para>
   </body>
</modulefunction>
''')
def gen2Time(val):
   'der encoded value not including tag or length'
   if not isinstance(val, types.StringType):
      raise DerError, 'argument should be a string'
   t = time.strptime(val, '%Y%m%d%H%M%SZ')
   return int(time.mktime(t))

_addFragment('''
<modulefunction>
   <header>
      <name>time2gen</name>
      <parameter>time</parameter>
   </header>
   <body>
      <para>
         This is a helper function for turning an integer into a
         GeneralizedTime string.  It isn't built into the encoder since the
         various functions which are used to manipulate the tm structure
         are notoriously unreliable.
      </para>
   </body>
</modulefunction>
''')
def time2gen(val):
   'numerical time value like time_t'
   val = int(val)
   t = time.gmtime(val)
   return time.strftime('%Y%m%d%H%M%SZ', t)

_addFragment('''
<method>
   <header>
      <name>ip42oct</name>
      <parameter>ip</parameter>
   </header>
   <body>
      <para>
         <parameter>ip</parameter> should be a list or tuple of integers,
         from 0 to 256.
      </para>
      <example>
         <title>Setting <classname>IpAddress</classname></title>
         <programlisting>
            ip = IpAddress()
            ip.set( ip42oct(192, 168, 0, 231) )
         </programlisting>
      </example>
   </body>
</method>
''')
def ip42oct(val0, val1, val2, val3):
   return chr(val0) + chr(val1) + chr(val2) + chr(val3)

_addFragment('''
<method>
   <header>
      <name>oct2ip4</name>
      <parameter>val</parameter>
   </header>
   <body>
      <para>
         Returns a tuple of 4 integers, from 0 to 256.
      </para>
   </body>
</method>
''')
def oct2ip4(val):
   if not isinstance(val, types.StringType) or len(val) != 4:
      raise DerError, 'parameter should be string of 4 characters'
   return ( ord(val[0]), ord(val[1]), ord(val[2]), ord(val[3]) ) 

#---------- certificate support ----------#
class TbsCertificate(Sequence):
   def __init__(self, optional=0, default=''):

      self.version = Integer()
      self.explicitVersion = Explicit( CLASS_CONTEXT, FORM_CONSTRUCTED, 0, self.version, 0, 'oAMCAQA=\n' )

      self.serial = Integer()
      self.signature = AlgorithmIdentifier()
      self.issuer = Name()
      self.subject = Name()
      self.subjectPublicKeyInfo = SubjectPublicKeyInfo()

      self.validity = Validity()

      self.issuerUniqueID = BitString(1)
      self.issuerUniqueID.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 1 )
      self.subjectUniqueID = BitString(1)
      self.subjectUniqueID.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 2 )

      self.extensions = Extensions()
      self.explicitExtensions = Explicit( CLASS_CONTEXT, FORM_CONSTRUCTED, 3, self.extensions, 1 )

      contents =  [   
                     self.explicitVersion, 
                     self.serial, 
                     self.signature,
                     self.issuer,
                     self.validity,
                     self.subject,
                     self.subjectPublicKeyInfo,
                     self.issuerUniqueID,
                     self.subjectUniqueID,
                     self.explicitExtensions
                  ]

      Sequence.__init__(self, contents, optional, default)

class Validity(Sequence):
   def __init__(self, optional=0, default=''):
      Time = lambda : Choice({ 'generalTime' : GeneralizedTime(), 'utcTime' : UtcTime() })
      self.notBefore = Time()
      self.notAfter = Time()
      contents = [self.notBefore, self.notAfter]
      Sequence.__init__(self, contents, optional, default)

class DirectoryString(Choice):
   def __init__(self, optional=0, default=''):
      choices =   {  'teletexString'            :  T61String(),
                     'printableString'          :  PrintableString(),
                     'universalString'          :  UniversalString(),
                     'bmpString'                :  BmpString(),
                     'utf8String'               :  Utf8String()   } 

      Choice.__init__(self, choices, optional, default)

class AttributeTypeAndValue(Sequence):
   def __init__(self, optional=0, default=''):
      self.type = Oid()
      self.dirstr = DirectoryString()
      contents = [ self.type, self.dirstr ] 
      Sequence.__init__(self, contents, optional, default)

class RelativeDistinguishedName(SetOf):
   def __init__(self, optional=0, default=''):
      SetOf.__init__(self, AttributeTypeAndValue, optional, default)

class Name(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, RelativeDistinguishedName, optional, default)

class AlgorithmIdentifier(Sequence):
   def __init__(self, optional=0, default=''):
      self.algorithm = Oid()
      self.parameters = Null()
      contents = [self.algorithm, self.parameters]
      Sequence.__init__(self, contents, optional, default)

class SubjectPublicKeyInfo(Sequence):
   def __init__(self, optional=0, default=''):
      self.algorithmId = AlgorithmIdentifier()
      self.subjectPublicKey = AltBitString()
      contents =  [ self.algorithmId, self.subjectPublicKey ]
      Sequence.__init__(self, contents, optional, default)

class Extensions(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, Extension, optional, default)

_addFragment('''
<class>
   <header>
      <name>Certificate</name>
      <super>Sequence</super>
   </header>
   <body>
      <example>
         <title>Setting <classname>Certificate</classname></title>
         <programlisting>
      rsa = POW.Asymmetric()
      cert = POW.pkix.Certificate()
      cert.setVersion(1)
      cert.setSerial(5)

      name = ( (( o2i('countryName'), ('printableString', 'GB') ),), 
               (( o2i('stateOrProvinceName'), ('printableString', 'Hertfordshire') ),), 
               (( o2i('organizationName'), ('printableString', 'The House') ),),
               (( o2i('commonName'), ('printableString', 'Client') ),) ) 

      cert.setIssuer(name)
      cert.setSubject(name)

      now = POW.pkix.time2gen( time.time() )
      then = POW.pkix.time2gen(time.time() + 60*60*24*365*12)
      cert.setNotBefore( ('generalTime',  now) )
      cert.setNotAfter( ( 'generalTime',  then) )
      cert.setIssuerUniqueID((1,0,1,0))
      cert.setSubjectUniqueID((1,0,0,1))
      cert.sign(rsa, POW.MD5_DIGEST)
         </programlisting>
      </example>
   </body>
</class>
''')

class Certificate(Sequence):

   _addFragment('''
   <constructor>
      <header>
         <memberof>Certificate</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')
   def __init__(self, optional=0, default=''):
      self.tbs = TbsCertificate()
      self.signatureAlgorithm = AlgorithmIdentifier()
      self.signatureValue = AltBitString()
      contents = [ self.tbs, self.signatureAlgorithm, self.signatureValue ] 
      Sequence.__init__(self, contents, optional, default)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>setVersion</name>
         <parameter>version</parameter>
      </header>
      <body>
         <para>
            This function sets an <classname>Integer</classname> object.  0
            indicates a version 1 certificate, 1 a version 2 certificate and 2 a
            version 3 certificate.
         </para>
      </body>
   </method>
   ''')
   def setVersion(self, version):
      self.tbs.version.set(version)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>getVersion</name>
      </header>
      <body>
         <para>
            This function returns whatever the version object is set to,
            this should be 0, 1 or 2. 
         </para>
      </body>
   </method>
   ''')
   def getVersion(self):
      return self.tbs.version.get()

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>setSerial</name>
         <parameter>serial</parameter>
      </header>
      <body>
         <para>
            This function sets an <classname>Integer</classname> object.
            No two certificates issued should ever have the same serial
            number.  
         </para>
      </body>
   </method>
   ''')
   def setSerial(self, serial):
      self.tbs.serial.set(serial)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>getVersion</name>
      </header>
      <body>
         <para>
            This function returns whatever the serial object is set to.
         </para>
      </body>
   </method>
   ''')
   def getSerial(self):
      return self.tbs.serial.get()

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>setIssuer</name>
         <parameter>names</parameter>
      </header>
      <body>
         <para>
            This function sets an <classname>Name</classname> object.
            See <classname>Certificate</classname> class for an example.
         </para>
     </body>
   </method>
   ''')
   def setIssuer(self, issuer):
      self.tbs.issuer.set(issuer)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>getIssuer</name>
      </header>
      <body>
         <para>
            This function returns a complex tuple containing other tuples.
         </para>
      </body>
   </method>
   ''')
   def getIssuer(self):
      return self.tbs.issuer.get()

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>setSubject</name>
         <parameter>names</parameter>
      </header>
      <body>
         <para>
            This function sets an <classname>Name</classname> object.
            See <classname>Certificate</classname> class for an example.
         </para>
      </body>
   </method>
   ''')
   def setSubject(self, subject):
      self.tbs.subject.set(subject)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>getSubject</name>
      </header>
      <body>
         <para>
            This function returns a complex tuple containing other tuples.
         </para>
      </body>
   </method>
   ''')
   def getSubject(self):
      return self.tbs.subject.get()

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>setNotBefore</name>
         <parameter>time</parameter>
      </header>
      <body>
         <para>
            This function sets a <classname>Choice</classname> object.
            It can be either a <classname>GeneralTime</classname> or
            <classname>UTCTime</classname> object.  The functions
            <function>gen2time</function>, <function>utc2time</function>, 
            <function>time2gen</function> and <function>time2utc</function>
            can be used to convert to and from integer times and their
            string representation.
         </para>
         <example>
            <title><function>setNotBefore</function> method usage</title>
            <programlisting>
      cert = POW.pkix.Certificate()
      now = POW.pkix.time2gen( time.time() )
      cert.setNotBefore( ('generalTime',  now) )
            </programlisting>
         </example>
      </body>
   </method>
   ''')
   def setNotBefore(self, nb):
      self.tbs.validity.notBefore.set(nb)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>getNotBefore</name>
      </header>
      <body>
         <para>
            This function returns a tuple indicating which type of time was
            stored and its value.  See <function>setNotBefore</function> for details.
         </para>
      </body>
   </method>
   ''')
   def getNotBefore(self):
      return self.tbs.validity.notBefore.get()

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>setNotAfter</name>
         <parameter>time</parameter>
      </header>
      <body>
         <para>
            This function sets a <classname>Choice</classname> object.
            See <function>setNotBefore</function> for details.
         </para>
      </body>
   </method>
   ''')
   def setNotAfter(self, na):
      self.tbs.validity.notAfter.set(na)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>getNotAfter</name>
      </header>
      <body>
         <para>
            This function returns a tuple indicating which type of time was
            stored and its value.  See <function>setNotBefore</function> for details.
         </para>
      </body>
   </method>
   ''')
   def getNotAfter(self):
      return self.tbs.validity.notAfter.get()

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>setIssuerUniqueID</name>
         <parameter>id</parameter>
      </header>
      <body>
         <para>
            This function sets a <classname>BitString</classname> object.
            This is part of the X509v2 standard and is quite poorly
            regarded in general, its use is not recommended.  It is set
            using the normal <classname>BitString</classname> method, that
            is with a sequence of true/false objects.
         </para>
      </body>
   </method>
   ''')
   def setIssuerUniqueID(self, id):
      self.tbs.issuerUniqueID.set(id)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>getIssuerUniqueID</name>
      </header>
      <body>
         <para>
            This function returns a tuple of integers, 1 or 0.
         </para>
      </body>
   </method>
   ''')
   def getIssuerUniqueID(self):
      return self.tbs.issuerUniqueID.get()

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>setSubjectUniqueID</name>
         <parameter>id</parameter>
      </header>
      <body>
         <para>
            This function sets a <classname>BitString</classname> object.
            This is part of the X509v2 standard and is quite poorly
            regarded in general, its use is not recommended.  It is set
            using the normal <classname>BitString</classname> method, that
            is with a sequence of true/false objects.
         </para>
      </body>
   </method>
   ''')
   def setSubjectUniqueID(self, id):
      self.tbs.subjectUniqueID.set(id)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>getSubjectUniqueID</name>
      </header>
      <body>
         <para>
            This function returns a tuple of integers, 1 or 0.
         </para>
      </body>
   </method>
   ''')
   def getSubjectUniqueID(self):
      return self.tbs.subjectUniqueID.get()

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>setExtensions</name>
         <parameter>extns</parameter>
      </header>
      <body>
         <para>
            This method sets an <classname>Extensions</classname> object,
            defined as SEQUENCE OF Extension.  The parameter
            <parameter>extns</parameter> should consist of a list or tuple
            of values suitable to set an extension.  See the extension
            class for details.
         </para>
      </body>
   </method>
   ''')
   def setExtensions(self, extns):
      self.tbs.extensions.set(extns)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>getExtensions</name>
      </header>
      <body>
         <para>
            This function returns a tuple of
            <classname>Extension</classname> values.  See
            <classname>Extension</classname> for details.
         </para>
      </body>
   </method>
   ''')
   def getExtensions(self):
      return self.tbs.extensions.get()

   def getExtension(self, oid):
      for x in self.getExtensions():
         if x[0] == oid:
            return x
      return None

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>sign</name>
         <parameter>rsa</parameter>
         <parameter>digestType</parameter>
      </header>
      <body>
         <para>
            This function updates structured of the
            <classname>Certificate</classname> and
            <constant>tbs</constant> as appropriate and performs the
            specified digest on the <constant>tbs</constant> and set
            <constant>signedText</constant> to signed the digest.  
         </para>
      </body>
   </method>
   ''')
   def sign(self, rsa, digestType):
      driver = getCryptoDriver()
      oid = driver.getOID(digestType)
      self.tbs.signature.set([oid, None])
      signedText = driver.sign(rsa, oid, self.tbs.toString())
      self.signatureAlgorithm.set([oid, None])
      self.signatureValue.set(signedText)

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>verify</name>
         <parameter>rsa</parameter>
      </header>
      <body>
         <para>
            This function works out what kind of digest was used to
            during signing, calculates the digest of   
            <constant>tbs</constant> and verifies the envelope using the
            key.  
         </para>
      </body>
   </method>
   ''')
   def verify(self, rsa):
      driver = getCryptoDriver()
      oid = self.signatureAlgorithm.get()[0]
      return driver.verify(rsa, oid, self.tbs.toString(), self.signatureValue.get())

#---------- certificate support ----------#
#---------- CRL ----------#

class RevokedCertificate(Sequence):
   def __init__(self, optional=0, default=''):
      self.userCertificate = Integer()
      self.revocationDate = Choice( { 'generalTime' : GeneralizedTime(), 'utcTime' : UtcTime() } )
      self.crlEntryExtensions = Extensions(1)
      contents = [ self.userCertificate, self.revocationDate, self.crlEntryExtensions ] 
      Sequence.__init__(self, contents, optional, default)

class RevokedCertificates(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, RevokedCertificate, optional, default)

class TbsCertList(Sequence):
   def __init__(self, optional=0, default=''):
      self.version = Integer(1)
      self.signature = AlgorithmIdentifier()
      self.issuer = Name()
      self.thisUpdate = Choice( { 'generalTime' : GeneralizedTime(), 'utcTime' : UtcTime() } )
      self.nextUpdate = Choice( { 'generalTime' : GeneralizedTime(), 'utcTime' : UtcTime() }, 1 )
      self.revokedCertificates = RevokedCertificates(1)
      self.crlExtensions = Extensions()
      self.explicitCrlExtensions = Explicit( CLASS_CONTEXT, FORM_CONSTRUCTED, 0, self.crlExtensions, 1 )
      contents = [   self.version, 
                     self.signature,
                     self.issuer,
                     self.thisUpdate, 
                     self.nextUpdate,
                     self.revokedCertificates,
                     self.explicitCrlExtensions    ] 
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>CertificateList</name>
      <super>Sequence</super>
   </header>
   <body>
      <example>
         <title>Setting <classname>CertificateList</classname></title>
         <programlisting>
      now = POW.pkix.time2gen( time.time() )
      then = POW.pkix.time2gen(time.time() + 60*60*24*365*12)
      rsa = POW.Asymmetric()

      crl = POW.pkix.CertificateList()
      crl.setThisUpdate( ('generalTime', now ) )

      name = ( (( o2i('countryName'), ('printableString', 'GB') ),), 
               (( o2i('stateOrProvinceName'), ('printableString', 'Hertfordshire') ),), 
               (( o2i('organizationName'), ('printableString', 'The House') ),),
               (( o2i('commonName'), ('printableString', 'Client') ),) ) 

      myRevocations = (
                        (1, ('generalTime', now), ()),
                        (2, ('generalTime', now), ()),
                        (3, ('generalTime', now), (( o2i('cRLReason'), 0, 1),)) 
                      ) 

      crl.setIssuer(name)
      crl.setRevokedCertificates( myRevocations )

      crl.sign(rsa, POW.MD5_DIGEST)
         </programlisting>
      </example>
   </body>
</class>
''')
class CertificateList(Sequence):
   _addFragment('''
   <constructor>
      <header>
         <memberof>CertificateList</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''')
   def __init__(self, optional=0, default=''):
      self.tbs = TbsCertList()
      self.signatureAlgorithm = AlgorithmIdentifier()
      self.signature = AltBitString()
      contents = [self.tbs, self.signatureAlgorithm, self.signature]
      Sequence.__init__(self, contents, optional, default)

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>setVersion</name>
         <parameter>version</parameter>
      </header>
      <body>
         <para>
            This function sets an <classname>Integer</classname> object.  0
            indicates a version 1 CRL, and 1 a version 2 CRL.
         </para>
      </body>
   </method>
   ''')
   def setVersion(self, version):
      self.tbs.version.set(version)

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>getVersion</name>
      </header>
      <body>
         <para>
            This function returns whatever the version object is set to,
            this should be 0, 1 or 2. 
         </para>
      </body>
   </method>
   ''')
   def getVersion(self):
      return self.tbs.version.get()

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>setIssuer</name>
         <parameter>names</parameter>
      </header>
      <body>
         <para>
            This function sets an <classname>Name</classname> object.
         </para>
     </body>
   </method>
   ''')
   def setIssuer(self, issuer):
      self.tbs.issuer.set(issuer)

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>getIssuer</name>
      </header>
      <body>
         <para>
            This function returns a complex tuple containing other tuples.
         </para>
      </body>
   </method>
   ''')
   def getIssuer(self):
      return self.tbs.issuer.get()

   _addFragment('''
   <method>
      <header>
         <memberof>setThisUpdate</memberof>
         <name>setNotBefore</name>
         <parameter>time</parameter>
      </header>
      <body>
         <para>
            This function sets a <classname>Choice</classname> object.
            It can be either a <classname>GeneralTime</classname> or
            <classname>UTCTime</classname> object.  The functions
            <function>gen2time</function>, <function>utc2time</function>, 
            <function>time2gen</function> and <function>time2utc</function>
            can be used to convert to and from integer times and their
            string representation.
         </para>
         <example>
            <title><function>setNotBefore</function> method usage</title>
            <programlisting>
      crl = POW.pkix.CertificateList()
      now = POW.pkix.time2gen( time.time() )
      crl.setNotBefore( ('generalTime',  now) )
            </programlisting>
         </example>
      </body>
   </method>
   ''')
   def setThisUpdate(self, nu):
      self.tbs.thisUpdate.set(nu)

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>getThisUpdate</name>
      </header>
      <body>
         <para>
            This function returns a tuple containing two strings. The first
            is either 'utcTime' or 'generalTime' and the second is the time
            value as a string.
         </para>
      </body>
   </method>
   ''')
   def getThisUpdate(self):
      return self.tbs.thisUpdate.get()

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>setNextUpdate</name>
      </header>
      <body>
         <para>
            See set <function>setThisUpdate</function>.
         </para>
      </body>
   </method>
   ''')
   def setNextUpdate(self, nu):
      self.tbs.nextUpdate.set(nu)

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>getNextUpdate</name>
      </header>
      <body>
         <para>
            See set <function>getThisUpdate</function>.
         </para>
      </body>
   </method>
   ''')
   def getNextUpdate(self):
      return self.tbs.nextUpdate.get()

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>setExtensions</name>
         <parameter>extns</parameter>
      </header>
      <body>
         <para>
            This method sets an <classname>Extensions</classname> object,
            defined as SEQUENCE OF Extension.  The parameter
            <parameter>extns</parameter> should consist of a list or tuple
            of values suitable to set an extension.  See the extension
            class for details.
         </para>
      </body>
   </method>
   ''')
   def setExtensions(self, extns):
      self.tbs.crlExtensions.set(extns)

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>getExtensions</name>
      </header>
      <body>
         <para>
            This function returns a tuple of
            <classname>Extension</classname> values.  See
            <classname>Extension</classname> for details.
         </para>
      </body>
   </method>
   ''')
   def getExtensions(self):
      return self.tbs.crlExtensions.get()

   def getExtension(self, oid):
      for x in self.getExtensions():
         if x[0] == oid:
            return x
      return None

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>setRevokedCertificates</name>
      </header>
      <body>
         <para>
            This function sets a sequence of
            <classname>revokedCertificate</classname> objects.
            This object is optional.  See
            <classname>CertificateList</classname> for an example of its
            use.
         </para>
      </body>
   </method>
   ''')
   def setRevokedCertificates(self, rc):
      self.tbs.revokedCertificates.set(rc)

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>getRevokedCertificates</name>
      </header>
      <body>
         <para>
            This function return a sequence of
            <classname>revokedCertificate</classname> objects or None.
         </para>
      </body>
   </method>
   ''')
   def getRevokedCertificates(self):
      return self.tbs.revokedCertificates.get()

   _addFragment('''
   <method>
      <header>
         <memberof>Certificate</memberof>
         <name>sign</name>
      </header>
      <body>
         <para>
            This function updates structured of the
            <classname>certificateList</classname> and
            <classname>tBSCertList</classname> as appropriate, performs the
            specified digest on the <classname>tBSCertList</classname> and sets
            <constant>signedValue</constant> to signed the digest.  
         </para>
      </body>
   </method>
   ''')
   def sign(self, rsa, digestType):
      driver = getCryptoDriver()
      oid = driver.getOID(digestType)
      self.tbs.signature.set([oid, None])
      signedText = driver.sign(rsa, oid, self.tbs.toString())
      self.signatureAlgorithm.set([oid, None])
      self.signature.set(signedText)

   _addFragment('''
   <method>
      <header>
         <memberof>CertificateList</memberof>
         <name>verify</name>
      </header>
      <body>
         <para>
            This function works out what kind of digest was used to during
            signing, calculates the digest of
            <classname>tBSCertList</classname> and verifies the
            <constant>signedText</constant> using the key.  
         </para>
      </body>
   </method>
   ''')
   def verify(self, rsa):
      driver = getCryptoDriver()
      oid = self.signatureAlgorithm.get()[0]
      return driver.verify(rsa, oid, self.tbs.toString(), self.signature.get())

#---------- CRL ----------#
#---------- PKCS10 ----------#

# My ASN.1-foo (and perhaps this ASN.1 implementation) isn't quite up
# to X.501 or PKCS #10, so this is partly based on a dump of what
# OpenSSL generates, and doesn't handle attributes other than X.509v3
# extensions.

class PKCS10AttributeSet(SetOf):
   def __init__(self, optional=0, default=''):
      SetOf.__init__(self, Extensions, optional, default)

class PKCS10AttributeChoice(Choice):
   def __init__(self, optional=0, default=''):
      choices = { 'single' : Extensions(),
                  'set'    : PKCS10AttributeSet() }
      Choice.__init__(self, choices, optional, default)

class PKCS10Attributes(Sequence):
   def __init__(self, optional=1, default=''):
      self.oid = Oid()
      self.val = PKCS10AttributeChoice()
      contents = [ self.oid, self.val ]
      Sequence.__init__(self, contents, optional, default)

class CertificationRequestInfo(Sequence):
   def __init__(self, optional=0, default=''):
      self.version = Integer()
      self.subject = Name()
      self.subjectPublicKeyInfo = SubjectPublicKeyInfo()
      self.attributes = PKCS10Attributes()
      self.explicitAttributes = Explicit(CLASS_CONTEXT, FORM_CONSTRUCTED, 0, self.attributes)
      contents = [ self.version, self.subject, self.subjectPublicKeyInfo, self.explicitAttributes ]
      Sequence.__init__(self, contents, optional, default)

class CertificationRequest(Sequence):
   def __init__(self, optional=0, default=''):
      self.certificationRequestInfo = CertificationRequestInfo()
      self.signatureAlgorithm = AlgorithmIdentifier()
      self.signatureValue = AltBitString()
      contents = [ self.certificationRequestInfo, self.signatureAlgorithm, self.signatureValue ] 
      Sequence.__init__(self, contents, optional, default)

   def sign(self, rsa, digestType):
      driver = getCryptoDriver()
      oid = driver.getOID(digestType)
      self.certificationRequestInfo.subjectPublicKeyInfo.fromString(driver.toPublicDER(rsa))
      signedText = driver.sign(rsa, oid, self.certificationRequestInfo.toString())
      self.signatureAlgorithm.set([oid, None])
      self.signatureValue.set(signedText)

   def verify(self):
      driver = getCryptoDriver()
      oid = self.signatureAlgorithm.get()[0]
      rsa = driver.fromPublicDER(self.certificationRequestInfo.subjectPublicKeyInfo.toString())
      return driver.verify(rsa, oid, self.certificationRequestInfo.toString(), self.signatureValue.get())

   def getExtensions(self):
      oid = self.certificationRequestInfo.attributes.oid.get()
      if oid is None:
         return ()
      if oid != (1, 2, 840, 113549, 1, 9, 14) or \
         self.certificationRequestInfo.attributes.val.choice != "set" or \
         len(self.certificationRequestInfo.attributes.val.choices["set"]) > 1:
         raise DerError, "failed to understand X.501 Attribute encoding, sorry: %s" % self.get()
      return self.certificationRequestInfo.attributes.val.choices["set"][0].get()

   def getExtension(self, oid):
      for x in self.getExtensions():
         if x[0] == oid:
            return x
      return None

   def setExtensions(self, exts):
      self.certificationRequestInfo.attributes.oid.set((1, 2, 840, 113549, 1, 9, 14))
      self.certificationRequestInfo.attributes.val.set(("set", [exts]))

#---------- PKCS10 ----------#
#---------- GeneralNames object support ----------#
class OtherName(Sequence):
   def __init__(self, optional=0, default=''):
      self.typeId = Oid()
      self.any = Any()
      contents = [self.typeId, self.any]
      Sequence.__init__(self, contents, optional, default)

class EdiPartyName(Sequence):
   def __init__(self, optional=0, default=''):
      self.nameAssigner = DirectoryString()
      self.partyName = DirectoryString()
      self.explicitNameAssigner = Explicit( CLASS_CONTEXT, FORM_CONSTRUCTED, 0, self.nameAssigner, 1 )
      self.explicitPartyName = Explicit( CLASS_CONTEXT, FORM_CONSTRUCTED, 1, self.partyName )
      contents = [ self.explicitNameAssigner, self.explicitPartyName ]
      Sequence.__init__(self, contents, optional, default)

class IpAddress(OctetString):
   pass

class GeneralName(Choice):
   def __init__(self, optional=0, default=''):

      otherName = OtherName()
      otherName.implied( CLASS_CONTEXT, FORM_CONSTRUCTED, 0 )
      rfc822Name = IA5String()
      rfc822Name.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 1 )
      dnsName = IA5String()
      dnsName.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 2 )
      directoryName = Name()
      explicitDirectoryName = Explicit( CLASS_CONTEXT, FORM_CONSTRUCTED, 4, directoryName)
      ediPartyName = EdiPartyName()
      ediPartyName.implied( CLASS_CONTEXT, FORM_CONSTRUCTED, 5 )
      uri = IA5String()
      uri.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 6 )
      ipAddress = IpAddress()
      ipAddress.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 7 )
      registeredId = Oid()
      registeredId.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 8 )

      choices =   {  'otherName'                :  otherName ,
                     'rfc822Name'               :  rfc822Name ,
                     'dNSName'                  :  dnsName ,
                     'directoryName'            :  explicitDirectoryName ,
                     'ediPartyName'             :  ediPartyName ,
                     'uri'                      :  uri ,
                     'iPAddress'                :  ipAddress ,
                     'registeredId'             :  registeredId  }

      Choice.__init__(self, choices, optional, default)

class GeneralNames(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, GeneralName, optional, default)

#---------- GeneralNames object support ----------#
#---------- X509v3 extensions ----------#

_addFragment('''
<class>
   <header>
      <name>BasicConstraints</name>
      <super>Sequence</super>
   </header>
   <body>
      <para>
         This little extension has recently caused plenty of problems for
         several large organisations.  It consist of a
         <classname>Boolean</classname> and an
         <classname>Integer</classname>.  The first indicates if the owner
         is a CA, the second indicates how long a chain of CAs you should
         trust which the subject of this certificate trusts.  
      </para>
      <example>
         <title>Setting <classname>BasicConstraints</classname></title>
         <programlisting>
            bc = BasicConstraints()
            bc.set( (1, 1) )
         </programlisting>
      </example>
   </body>
</class>
''')
class BasicConstraints(Sequence):
   _addFragment('''
   <constructor>
      <header>
         <memberof>BasicConstraints</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''') 
   def __init__(self, optional=0, default=''):
      self.ca = Boolean(0, 'AQEA\n')
      self.pathLenConstraint = Integer(1)
      contents = [self.ca, self.pathLenConstraint]
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>KeyUsage</name>
      <super>BitString</super>
   </header>
</class>
''')
class KeyUsage(BitString):
   pass

_addFragment('''
<class>
   <header>
      <name>SubjectAltName</name>
      <super>GeneralNames</super>
   </header>
</class>
''')
class SubjectAltName(GeneralNames):
   pass

_addFragment('''
<class>
   <header>
      <name>IssuerAltName</name>
      <super>GeneralNames</super>
   </header>
</class>
''')
class IssuerAltName(GeneralNames):
   pass

_addFragment('''
<class>
   <header>
      <name>SubjectKeyIdentifier</name>
      <super>OctetString</super>
   </header>
</class>
''')
class SubjectKeyIdentifier(OctetString):
   pass

_addFragment('''
<class>
   <header>
      <name>AuthorityKeyIdentifier</name>
      <super>Sequence</super>
   </header>
   <body>
      <para>
      </para>
      <example>
         <title>Setting <classname>AuthorityKeyIdentifier</classname></title>
         <programlisting>
      id = AuthorityKeyIdentifier()
      authdigest = POW.Digest( POW.SHA1_DIGEST )
      authdigest.update(rsa.derWrite(POW.RSA_PUBLIC_KEY))
      keyHash = authdigest.digest()
      id.set( (keyHash, None, None) )
         </programlisting>
      </example>
   </body>

</class>
''')
class AuthorityKeyIdentifier(Sequence):
   _addFragment('''
   <constructor>
      <header>
         <memberof>AuthorityKeyIdentifier</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''') 
   def __init__(self, optional=0, default=''):
      self.keyIdentifier = OctetString(1)
      self.keyIdentifier.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 0 )
      self.authorityCertIssuer = GeneralNames(1)
      self.authorityCertIssuer.implied( CLASS_CONTEXT, FORM_CONSTRUCTED, 1 )
      self.authorityCertSerialNumber = Integer(1)
      self.authorityCertSerialNumber.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 2 )
      contents = [self.keyIdentifier, self.authorityCertIssuer, self.authorityCertSerialNumber]
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>PrivateKeyUsagePeriod</name>
      <super>Sequence</super>
   </header>
   <body>
      <example>
         <title>Setting <classname>PrivateKeyUsagePeriod</classname></title>
         <programlisting>
      period = PrivateKeyUsagePeriod()
      period.set( ( time2gen( time.time() ), None) )
         </programlisting>
      </example>
   </body>
</class>
''')
class PrivateKeyUsagePeriod(Sequence):
   _addFragment('''
   <constructor>
      <header>
         <memberof>PrivateKeyUsagePeriod</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''') 
   def __init__(self, optional=0, default=''):
      self.notBefore = GeneralizedTime()
      self.notBefore.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 0 )
      self.notAfter = GeneralizedTime()
      self.notAfter.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 1 )
      contents =  [self.notBefore, self.notAfter]
      Sequence.__init__(self, contents, optional, default)

class DisplayText(Choice):
   def __init__(self, optional=0, default=''):
      choices =   {  'visibleString'            :  VisibleString(),
                     'bmpString'                :  BmpString(),
                     'utf8String'               :  Utf8String()   } 

      Choice.__init__(self, choices, optional, default)

class NoticeNumbers(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, Integer, optional, default)

class NoticeReference(Sequence):
   def __init__(self, optional=0, default=''):
      self.organization = DisplayText()
      self.noticeNumbers = NoticeNumbers()
      contents =  [self.organization, self.noticeNumbers]
      Sequence.__init__(self, contents, optional, default)

class UserNotice(Sequence):
   def __init__(self, optional=0, default=''):
      self.noticeRef = NoticeReference(1)
      self.explicitText = DisplayText(1)
      contents =  [self.noticeRef, self.explicitText]
      Sequence.__init__(self, contents, optional, default)

class Qualifier(Choice):
   def __init__(self, optional=0, default=''):
      choices =   {  'cPSuri'       :  IA5String(),
                     'userNotice'   :  UserNotice()  }

      Choice.__init__(self, choices, optional, default)

class PolicyQualifierInfo(Sequence):
   def __init__(self,  optional=0, default=''):
      self.policyQualifierId = Oid()
      self.qualifier = Qualifier()
      contents =  [self.policyQualifierId, self.qualifier]
      Sequence.__init__(self, contents, optional, default)

class PolicyQualifiers(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, PolicyQualifierInfo, optional, default)

class PolicyInformation(Sequence):
   def __init__(self, optional=0, default=''):
      self.policyIdentifier = Oid()
      self.policyQualifiers = PolicyQualifiers(1)
      contents =  [self.policyIdentifier, self.policyQualifiers]
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>CertificatePolicies</name>
      <super>SequenceOf</super>
   </header>
   <body>
      <example>
         <title>Setting <classname>CertificatePolicies</classname></title>
         <programlisting>
       data = ( 
                  ( o2i('id-cti-ets-proofOfReceipt'), (
                     (o2i('cps'),     ('cPSuri', 'http://www.p-s.org.uk/policies/policy1')), 
                     (o2i('unotice'), (   'userNotice', 
                                          ((('visibleString', 'The House'),(1,2,3)), 
                                             ('visibleString', 'We guarentee nothing')))),
                  )),
                  ( o2i('id-cti-ets-proofOfOrigin'), (
                     (o2i('cps'), ('cPSuri', 'http://www.p-s.org.uk/policies/policy2')), 
                  ))
                )
      policies = CertificatePolicies()
      policies.set( data )
         </programlisting>
      </example>
   </body>
</class>
''')
class CertificatePolicies(SequenceOf):
   _addFragment('''
   <constructor>
      <header>
         <memberof>CertificatePolicies</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''') 
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, PolicyInformation, optional, default)

class DistributionPointName(Choice):
   def __init__(self, optional=0, default=''):
      fullName = GeneralNames()
      fullName.implied( CLASS_CONTEXT, FORM_CONSTRUCTED, 0 )
      nameRelativeToCRLIssuer = RelativeDistinguishedName()
      nameRelativeToCRLIssuer.implied( CLASS_CONTEXT, FORM_CONSTRUCTED, 1 )
   
      choices =   {  'fullName'                 :  fullName,
                     'nameRelativeToCRLIssuer ' :  nameRelativeToCRLIssuer  }

      Choice.__init__(self, choices, optional, default)

class DistributionPoint(Sequence):
   def __init__(self, optional=0, default=''):
      self.distributionPoint = DistributionPointName(1)
      self.explicitDistributionPoint = Explicit(CLASS_CONTEXT, FORM_CONSTRUCTED, 0, self.distributionPoint)
      self.reasons = BitString(1)
      self.reasons.implied( CLASS_CONTEXT, FORM_PRIMITIVE, 1 )
      self.cRLIssuer = GeneralNames(1)
      self.cRLIssuer.implied( CLASS_CONTEXT, FORM_CONSTRUCTED, 2 )
      contents =  [self.explicitDistributionPoint, self.reasons, self.cRLIssuer]
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>CRLDistrobutionPoints</name>
      <super>SequenceOf</super>
   </header>
   <body>
      <example>
         <title>Setting <classname>CRLDistrobutionPoints</classname></title>
         <programlisting>
      n1 =  ('directoryName',  
               (  (( o2i('countryName'), ('printableString', 'UK') ),), 
                  (( o2i('stateOrProvinceName'), ('printableString', 'Herts') ),), 
                  (( o2i('organizationName'), ('printableString', 'The House') ),),
                  (( o2i('commonName'), ('printableString', 'Shannon Works') ),) ) ) 

      n2 = ('iPAddress', POW.pkix.ip42oct(192,168,100,51)) 

      data = ( ( ('fullName',(n1, n2)), (1,1,1,1,1), (n1,) ), )
      points = CRLDistrobutionPoints()
      points.set( data )
         </programlisting>
      </example>
   </body>
</class>
''')
class CRLDistributionPoints(SequenceOf):
   _addFragment('''
   <constructor>
      <header>
         <memberof>CRLDistrobutionPoints</memberof>
         <parameter>optional=0</parameter>
         <parameter>default=''</parameter>
      </header>
   </constructor>
   ''') 
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, DistributionPoint, optional, default)

_addFragment('''
<class>
   <header>
      <name>CrlNumber</name>
      <super>Integer</super>
   </header>
</class>
''')
class CrlNumber(Integer):
   pass

_addFragment('''
<class>
   <header>
      <name>DeltaCrlIndicator</name>
      <super>Integer</super>
   </header>
</class>
''')
class DeltaCrlIndicator(Integer):
   pass

_addFragment('''
<class>
   <header>
      <name>InvalidityDate</name>
      <super>GeneralizedTime</super>
   </header>
</class>
''')
class InvalidityDate(GeneralizedTime):
   pass

_addFragment('''
<class>
   <header>
      <name>CrlReason</name>
      <super>Enum</super>
   </header>
</class>
''')
class CrlReason(Enum):
   pass

_addFragment('''
<class>
   <header>
      <name>IPAddressRange</name>
      <super>Sequence</super>
   </header>
</class>
''')
class IPAddressRange(Sequence):
   def __init__(self, optional=0, default=''):
      self.min = BitString()
      self.max = BitString()
      contents = [ self.min, self.max ]
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>IPAddressOrRange</name>
      <super>Choice</super>
   </header>
</class>
''')
class IPAddressOrRange(Choice):
   def __init__(self, optional=0, default=''):
      choices = { 'addressPrefix' : BitString(),
                  'addressRange'  : IPAddressRange() }
      Choice.__init__(self, choices, optional, default)

_addFragment('''
<class>
   <header>
      <name>IPAddressesOrRanges</name>
      <super>SequenceOf</super>
   </header>
</class>
''')
class IPAddressesOrRanges(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, IPAddressOrRange, optional, default)

_addFragment('''
<class>
   <header>
      <name>IPAddressChoice</name>
      <super>Choice</super>
   </header>
</class>
''')
class IPAddressChoice(Choice):
   def __init__(self, optional=0, default=''):
      choices = { 'inherit'             : Null(),
                  'addressesOrRanges'   : IPAddressesOrRanges() }
      Choice.__init__(self, choices, optional, default)

_addFragment('''
<class>
   <header>
      <name>IPAddressFamily</name>
      <super>Sequence</super>
   </header>
</class>
''')
class IPAddressFamily(Sequence):
   def __init__(self, optional=0, default=''):
      self.addressFamily = OctetString()
      self.ipAddressChoice = IPAddressChoice()
      contents = [ self.addressFamily, self.ipAddressChoice ]
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>IPAddrBlocks</name>
      <super>SequenceOf</super>
   </header>
   <body>
      <para>
         Implementation of RFC 3779 section 2.2.3.
      </para>
   </body>
</class>
''')
class IPAddrBlocks(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, IPAddressFamily, optional, default)

_addFragment('''
<class>
   <header>
      <name>ASRange</name>
      <super>Sequence</super>
   </header>
</class>
''')
class ASRange(Sequence):
   def __init__(self, optional=0, default=''):
      self.min = Integer()
      self.max = Integer()
      contents = [ self.min, self.max ]
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>ASIdOrRange</name>
      <super>Choice</super>
   </header>
</class>
''')
class ASIdOrRange(Choice):
   def __init__(self, optional=0, default=''):
      choices = { 'id'    : Integer(),
                  'range' : ASRange() }
      Choice.__init__(self, choices, optional, default)

_addFragment('''
<class>
   <header>
      <name>ASIdsOrRanges</name>
      <super>SequenceOf</super>
   </header>
</class>
''')
class ASIdsOrRanges(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, ASIdOrRange, optional, default)

_addFragment('''
<class>
   <header>
      <name>ASIdentifierChoice</name>
      <super>Choice</super>
   </header>
</class>
''')
class ASIdentifierChoice(Choice):
   def __init__(self, optional=0, default=''):
      choices = { 'inherit'       : Null(),
                  'asIdsOrRanges' : ASIdsOrRanges() }
      Choice.__init__(self, choices, optional, default)

_addFragment('''
<class>
   <header>
      <name>ASIdentifiers</name>
      <super>Sequence</super>
   </header>
   <body>
      <para>
         Implementation of RFC 3779 section 3.2.3.
      </para>
   </body>
</class>
''')
class ASIdentifiers(Sequence):
   def __init__(self, optional=0, default=''):
      self.asnum = ASIdentifierChoice()
      self.rdi   = ASIdentifierChoice()
      self.explicitAsnum = Explicit(CLASS_CONTEXT, FORM_CONSTRUCTED, 0, self.asnum, 1)
      self.explictRdi    = Explicit(CLASS_CONTEXT, FORM_CONSTRUCTED, 1, self.rdi,   1)
      contents = [ self.explicitAsnum, self.explictRdi ]
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>AccessDescription</name>
      <super>Sequence</super>
   </header>
</class>
''')
class AccessDescription(Sequence):
   def __init__(self, optional=0, default=''):
      self.accessMethod = Oid()
      self.accessLocation = GeneralName()
      contents = [ self.accessMethod, self.accessLocation ]
      Sequence.__init__(self, contents, optional, default)

_addFragment('''
<class>
   <header>
      <name>AuthorityInfoAccess</name>
      <super>SequenceOf</super>
   </header>
   <body>
      <para>
         Implementation of RFC 3280 section 4.2.2.1.
      </para>
   </body>
</class>
''')
class AuthorityInfoAccess(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, AccessDescription, optional, default)

_addFragment('''
<class>
   <header>
      <name>SubjectInfoAccess</name>
      <super>SequenceOf</super>
   </header>
   <body>
      <para>
         Implementation of RFC 3280 section 4.2.2.2.
      </para>
   </body>
</class>
''')
class SubjectInfoAccess(SequenceOf):
   def __init__(self, optional=0, default=''):
      SequenceOf.__init__(self, AccessDescription, optional, default)

#---------- X509v3 extensions ----------#

_addFragment('''
<class>
   <header>
      <name>Extension</name>
      <super>Sequence</super>
   </header>
   <body>
      <para>
         This class is a useful little object.  It is set by passing three
         values: an oid, an integer(a boolean really) and a value.  The
         boolean indicates if this extension is critical.  The value is
         used to set the extension once it has been created.  The oid
         is used to create the correct object which, to be fully supported it must
         be one of these:
         <simplelist>
            <member><classname>basicConstraints</classname></member>
            <member><classname>subjectAltName</classname></member>
            <member><classname>issuerAltName</classname></member>
            <member><classname>authorityKeyIdentifier</classname></member>
            <member><classname>privateKeyUsagePeriod</classname></member>
            <member><classname>certificatePolicies</classname></member>
            <member><classname>cRLDistributionPoints</classname></member>
            <member><classname>subjectKeyIdentifier</classname></member>
            <member><classname>keyUsage</classname></member>
            <member><classname>crlNumber</classname></member>
            <member><classname>deltaCrlIndicator</classname></member>
            <member><classname>invalidityDate</classname></member>
            <member><classname>crlReason</classname></member>
         </simplelist>
      </para>
      <example>
         <title>Setting <classname>Extension</classname></title>
         <programlisting>
            extn = Extension()
            email = ('rfc822Name', 'peter_shannon@yahoo.com')
            extn.set( (obj2oid('subjectAltName'),1, (email,)) )
         </programlisting>
      </example>
   </body>
</class>
''')
class Extension(Sequence):

   classMap =     {  
                      (2, 5, 29, 19)  :  BasicConstraints,             
                      (2, 5, 29, 17)  :  SubjectAltName,
                      (2, 5, 29, 18)  :  IssuerAltName,
                      (2, 5, 29, 35)  :  AuthorityKeyIdentifier,
                      (2, 5, 29, 16)  :  PrivateKeyUsagePeriod,
                      (2, 5, 29, 32)  :  CertificatePolicies,
                      (2, 5, 29, 31)  :  CRLDistributionPoints,
                      (2, 5, 29, 14)  :  SubjectKeyIdentifier,
                      (2, 5, 29, 15)  :  KeyUsage,
                      (2, 5, 29, 20)  :  CrlNumber,
                      (2, 5, 29, 27)  :  DeltaCrlIndicator,
                      (2, 5, 29, 24)  :  InvalidityDate,
                      (2, 5, 29, 21)  :  CrlReason,
                      (1, 3, 6, 1, 5, 5, 7, 1, 1)  : AuthorityInfoAccess,
                      (1, 3, 6, 1, 5, 5, 7, 1, 7)  : IPAddrBlocks,
                      (1, 3, 6, 1, 5, 5, 7, 1, 8)  : ASIdentifiers,
                      (1, 3, 6, 1, 5, 5, 7, 1, 11) : SubjectInfoAccess,
                  }
#   Missing -- fix later
#                                         extendedKeyUsage  
#                                         privateKeyUsagePeriod 
#                                         policyMappings 
#                                         nameConstraints 
#                                         policyConstraints 
#                                         subjectDirectoryAttributes 
#                                         instructionCode
#                                         issuingDistrobutionPoint

   def __init__(self, optional=0, default=''):
      self.extnID = Oid()
      self.critical = Boolean(0, 'AQEA')
      self.extnValue = OctetString()
      contents = [self.extnID, self.critical, self.extnValue]
      Sequence.__init__(self, contents, optional, default)

   _addFragment('''
   <method>
      <header>
         <memberof>Extension</memberof>
         <name>set</name>
         <parameter>values</parameter>
      </header>
      <body>
         <para>
            <parameter>values</parameter> should be a sequence of three
            values, the oid, critical marker and a value to set the
            extension.  If an unknown oid is passed to this function it
            will raise an exception.  <parameter>critical</parameter> is a
            boolean.  <parameter>value</parameter> will be used to set the
            extension after it has been created.
         </para>
      </body>
   </method>
   ''')
   def set(self, (oid, critical, val) ):
      self.extnID.set( oid )
      self.critical.set( critical )

      extnObj = None
      if self.classMap.has_key(oid):
         extnObj = self.classMap[oid]()
      else:
         if not (isinstance(oid, types.TupleType) or isinstance(oid, types.ListType)):
            raise DerError, 'the oid should be specified as a sequence of integers'
         else:
            raise DerError, 'unknown object extension %s' % oid

      try:
         extnObj.set( val )
         self.extnValue.set( extnObj.toString() )
      except DerError, e:
         raise DerError, 'failed to set %s, with:\n\t%s\nresulting in:\n\t%s' % (oid, val, `e`)

   _addFragment('''
   <method>
      <header>
         <memberof>Extension</memberof>
         <name>get</name>
      </header>
      <body>
         <para>
            There are several ways this function might fail to decode an
            extension.  Firstly if the extension was marked critical but if
            the oid cannot be mapped to a class or If a failure occurs decoding the
            <constant>extnValue</constant>, an exception will be raised.
            If a failure occurred and the extension was not marked critical it
            will return a tuple like this: <constant>(oid, critical,
            ())</constant>.  If no failures occur a tuple will be returned,
            containg the oid, critical and extension values.
         </para>
      </body>
   </method>
   ''')
   def get(self):
      oid = self.extnID.get()
      critical = self.critical.get()

      if self.classMap.has_key(oid):
         extnObj = self.classMap[oid]()
      else:
         if critical:
            raise DerError, 'failed to read critical extension %s' % str(oid)
         else:
            return (oid, critical, ())

      try:
         extnObj = self.classMap[oid]()
         extnObj.fromString(self.extnValue.get())
         value = extnObj.get()
      except:
         if critical:
            raise DerError, 'failed to read critical extension %s' % str(oid)
         else:
            return (oid, critical, ())

      return (oid, critical, value)
