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

import _oids, _objects, types

class OidData(object):
   def __init__(self):
      self.oids = _oids.data
      self.objs = _objects.data

   def obj2oid(self, obj):
      if not self.objs.has_key(obj):
         raise Exception, 'unknown object: %s' % obj
      return tuple(self.objs[obj]['oid'])
   
   def oid2obj(self, oid):
      if isinstance( oid, types.ListType ):
         oid = tuple(oid)
      if not self.oids.has_key(oid):
         raise Exception, 'unknown oid %s' % `oid`
      return self.oids[oid]['name']
            
