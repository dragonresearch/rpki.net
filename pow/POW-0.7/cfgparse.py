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

import string, re, types, pprint

def decodeOid(val):
   val = [int(val,16) for val in val.split(" ")][2:]
   arc12 = val[0]
   arc1, arc2 = divmod(arc12, 40)
   oids = [arc1,arc2]
   total = 0
   for byte in val[1:]:
      if byte & 0x80:
         total = (total << 7) | (byte ^ 0x80)
      else:
         total = (total << 7) | byte
         oids.append(total)
         total = 0
   return tuple(oids)

# for people out there who, like me, hate regexs(too easy to make mistakes
# with) I apologise profusely!

class Parser:
   def __init__(self, filename):
      self.file = filename
      self.handle = open(self.file)
      self.whiteMatch = re.compile(r'^\s*')
      self.hashMatch = re.compile(r'^#.*')
      self.warningMatch = re.compile(r'^Warning')
      self.oidNameMatch = re.compile(r'(^[\w\-\.\? ]*)(?:\([\w\-# ]*\)\s?)?(?:\()([\d ]*)(?:\))')
      self.oidMatch = re.compile(r'(?:^OID = )(.*)')
      self.commentMatch = re.compile(r'(?:^Comment = )(.*)')
      self.descriptionMatch = re.compile(r'(?:^Description = )(.*)')
      self.oids = {}
      self.objs = {}
      self.__parse()

   def __update(self, dict, line):
      m = self.oidMatch.match( line )
      if m:
         dict['hexoid'] = m.group(1)
         dict['oid'] = decodeOid(m.group(1))
         return 0
      else:
         m = self.commentMatch.match( line )
         if m:
            dict['comment'] = m.group(1)
            return 0
         else:
            m = self.descriptionMatch.match( line )
            if m:
               dict['description'] = m.group(1)
               n = self.oidNameMatch.match( m.group(1) )
               if n:
                  dict['name'] = string.strip( n.group(1) )
               else:
                  dict['name'] = m.group(1)
               return 0
            else:
               m = self.warningMatch.match( line )
               if m:
                  return 1
               else:
                  m = self.whiteMatch.match( line )
                  if m:
                     return 0
                  else:
                     m = self.hashMatch.match( line )
                     if m:
                        return 0
                     else:
                        raise Exception, 'unhandled pattern'

   def __parse(self):
      line = self.handle.readline()
      dict = {}
      complete = None
      while line:
         warning = self.__update( dict, line )

         if warning:
            complete = None
         elif complete:
            self.objs[ complete['name'] ] = complete
            self.oids[ complete['oid'] ] = complete
            complete = None

         if len(dict) == 5:
            complete = dict
            dict = {}

         line = self.handle.readline()

   def dumpobjs(self, path):
      file = open(path, 'w')
      file.write('data = ')
      pprint.pprint( self.objs, file )
      file.close()

   def dumpoids(self, path):
      file = open(path, 'w')
      file.write('data = ')
      pprint.pprint( self.oids, file )
      file.close()
