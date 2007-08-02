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
      self.whiteMatch = re.compile(r'^\s*$')
      self.hashMatch = re.compile(r'^#')
      self.warningMatch = re.compile(r'^Warning')
      self.oidMatch = re.compile(r'(?:^OID\s*=\s* )(.*)')
      self.commentMatch = re.compile(r'(?:^Comment\s*=\s*)(.*)')
      self.descriptionMatch = re.compile(r'(?:^Description\s*=\s*)(.*)')
      self.oids = {}
      self.objs = {}
      self.__parse()

   def __store(self, dict):
      self.objs[dict['name']] = dict
      self.oids[dict['oid' ]] = dict

   def __parse(self):
      dict = None
      broken = False
      for line in self.handle:
         m = self.oidMatch.match(line)
         if m:
            if dict and not broken:
               self.__store(dict)
            dict = { 'hexoid' : m.group(1),
                     'oid'    : decodeOid(m.group(1)) }
            broken = False
            continue
         if self.warningMatch.match(line):
            broken = True
            continue
         if self.whiteMatch.match(line) or self.hashMatch.match(line):
            continue
         m = self.commentMatch.match(line)
         if m:
            dict['comment'] = m.group(1)
            continue
         m = self.descriptionMatch.match(line)
         if m:
            dict['description'] = m.group(1)
            dict['name'] = m.group(1).strip().split(' ')[0]
            continue
         raise Exception, 'unhandled pattern'
      if dict and not broken:
         self.__store(dict)

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
