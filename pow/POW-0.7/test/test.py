#!/usr/bin/env python

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

import unittest, POW.pkix, POW._oids, base64, sys, os, socket, time, types, string, StringIO, pprint

if not os.path.isdir('working'):
   os.mkdir('working')

DEBUG = 0

o2i = POW.pkix.obj2oid

def wo(mystring):
   file = open('test.der', 'w')
   file.write(mystring)
   file.close()

def checkValue(constructor, val1):
   obj1 = constructor()
   obj1.set(val1)
   io = obj1.toString()
   if DEBUG:
      file = open('test.der', 'w')
      obj1.write(file)
      file.close()

   obj2 = constructor()
   obj2.fromString(io)
   val2 = obj2.get()
   if val2 == val1:
      return 1
   else:
      if DEBUG:
         print 'read result:', val2
      return 0

class DerEncodingTestCase(unittest.TestCase):
   'a small suite of tests for the most complex codings'

   def booleanTest(self):
      'test boolean support'
      print 
      self.failUnless( checkValue(POW.pkix.Boolean, 1), 'true was not presereved correctly')
      self.failUnless( checkValue(POW.pkix.Boolean, 0), 'false was not presereved correctly')

   def integerTest(self):
      'test integer support'
      print 
      for i in range(-5000, 5000):
         print 'checking codings for', i
         self.failUnless( checkValue(POW.pkix.Integer, i), '%i was not presereved correctly' % i)

   def oidTest(self):
      'test oid support'
      print 
      for oid in POW._oids.data.keys():
         print 'checking codings for', oid
         self.failUnless( checkValue(POW.pkix.Oid, oid), '%s was not presereved correctly' % `oid`)

   def bitStringTest(self):
      'test bitstring support'
      values = [
                  (0,), (1,), (0,0), (0,1), (1,0), (1,1), (0,1,0,1,0), (0,0,0,0,0,0,0),
                  (1,1,1,1,1,1,1,), (0,0,0,0,0,0,0,0), (1,1,1,1,1,1,1,1),
                  (0,0,0,0,0,0,0,0,0), (1,1,1,1,1,1,1,1,1,)
               ]
      print 
      for val in values:
         print 'checking codings for', val
         self.failUnless( checkValue(POW.pkix.BitString, val), '%s was not presereved correctly' % `val`)


class ComplexDerTestCase(unittest.TestCase):
   '''a suite of tests for testing encoding of defaults, optional, explicit,
   implied and choice objects'''

   def emptySeqTest(self):
      'checking coding of empty sequence object'
      seq = POW.pkix.Sequence([])
      try:
         seq.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      self.failUnless(seq.toString() == '0\x00', 'empty sequence encoded incorrectly')
      seq.fromString(seq.toString())
      self.failUnless(seq.get() == (), 'empty sequence decoded incorrectly')
      self.failUnless(seq.toString() == '0\x00', 'empty sequence encoded incorrectly')

   def seqOfSimpleTest(self):
      'checking coding of basic sequence object'
      seq = POW.pkix.Sequence([ POW.pkix.Integer(), POW.pkix.Boolean(), POW.pkix.T61String() ])
      try:
         seq.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      values = (64, 1, 'Hello World')
      seq.set( values )
      self.failUnless(seq.toString() == '0\x13\x02\x01@\x01\x01\xff\x14\x0bHello World', 'sequence of basic encoded incorrectly')
      seq.fromString(seq.toString())
      self.failUnless(seq.get() == values, 'sequence of basic decoded incorrectly')
      self.failUnless(seq.toString() == '0\x13\x02\x01@\x01\x01\xff\x14\x0bHello World', 'sequence of basic encoded incorrectly')

   def seqOfSeqTest(self):
      'checking coding of sequence of sequence object'
      seqa = POW.pkix.Sequence([ POW.pkix.Integer(), POW.pkix.Boolean(), POW.pkix.T61String() ])
      seqb = POW.pkix.Sequence([ seqa, POW.pkix.Integer(), POW.pkix.Boolean() ])
      try:
         seqb.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      values = ((64, 1, 'Hello World'), 128, 0)
      seqb.set( values )
      self.failUnless(seqb.toString() == '0\x1c0\x13\x02\x01@\x01\x01\xff\x14\x0bHello World\x02\x02\x00\x80\x01\x01\x00', 
                  'sequence of sequence encoded incorrectly')
      seqb.fromString(seqb.toString())
      self.failUnless(seqb.get() == values, 'sequence of sequence decoded incorrectly')
      self.failUnless(seqb.toString() == '0\x1c0\x13\x02\x01@\x01\x01\xff\x14\x0bHello World\x02\x02\x00\x80\x01\x01\x00', 
                  'sequence of sequence encoded incorrectly')

   def seqOfSimpleWithOptionalTest(self):
      'checking coding of sequence of basic objects with optional object'
      seq = POW.pkix.Sequence([ POW.pkix.Integer(1), POW.pkix.Boolean(), POW.pkix.T61String() ])
      try:
         seq.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      values = (None, 1, 'Hello World')
      seq.set(values)
      self.failUnless(seq.toString() == '0\x10\x01\x01\xff\x14\x0bHello World', 'sequence of basic with optional encoded incorrectly')
      seq.fromString(seq.toString())
      self.failUnless(seq.get() == values, 'sequence of basic with optional decoded incorrectly')
      self.failUnless(seq.toString() == '0\x10\x01\x01\xff\x14\x0bHello World', 'sequence of basic with optional encoded incorrectly')

   def seqOfSimpleWithDefaultTest(self):
      'checking coding of sequence of basic objects with default object'
      seq = POW.pkix.Sequence([ POW.pkix.Integer(), POW.pkix.Boolean(), POW.pkix.T61String(0, 'FAtIZWxsbyBXb3JsZA==\n') ])
      try:
         seq.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      values = (32, 1, None)
      seq.set( values )
      self.failUnless(seq.toString() == '0\x06\x02\x01 \x01\x01\xff', 'sequence of basic with default encoded incorrectly')
      seq.fromString(seq.toString())
      self.failUnless(seq.get() == (32,1,'Hello World'), 'sequence of basic with default decoded incorrectly') 
      self.failUnless(seq.toString() == '0\x06\x02\x01 \x01\x01\xff', 'sequence of basic with default encoded incorrectly')

   def seqOfOptionalSeqTest(self):
      'checking coding of sequence of optional sequence object'
      seq = POW.pkix.Sequence([ POW.pkix.Sequence([POW.pkix.Integer()],1) ])
      try:
         seq.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      rep = seq.toString()
      self.failUnless(seq.toString() == '0\x00', 'sequence of optional sequence encoded incorrectly')
      seq.fromString('0\x00')
      self.failUnless(seq.toString() == '0\x00', 'sequence of optional sequence encoded incorrectly')
      values = ((64,),)
      seq.set( values )
      self.failUnless(seq.toString() == '0\x050\x03\x02\x01@', 'sequence of set optional sequence encoded incorrectly')
      seq.fromString(seq.toString())
      self.failUnless(seq.get() == values, 'sequence of set optional sequence decoded incorrectly') 

   def seqOfPartiallySetOptionalSeqTest(self):
      'checking coding of sequence of optional sequence objects'
      seq = POW.pkix.Sequence([ POW.pkix.Sequence([POW.pkix.Integer(), POW.pkix.Integer()],1) ])
      try:
         seq.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(seq.toString() == '0\x00', 'sequence of optional sequence encoded incorrectly')
      seq.fromString('0\x00')
      self.failUnless(seq.toString() == '0\x00', 'sequence of optional sequence encoded incorrectly')
      values = ((7,None),)
      seq.set( values )
      self.failUnless(seq.toString() == '0\x00', 'sequence of set optional sequence encoded incorrectly')
      seq.fromString(seq.toString())
      values = ((7,14),)
      seq.set( values )
      self.failUnless(seq.toString() == '0\x080\x06\x02\x01\x07\x02\x01\x0e', 'sequence of set optional sequence encoded incorrectly')
      seq.fromString('0\x080\x06\x02\x01\x07\x02\x01\x0e')
      self.failUnless(seq.toString() == '0\x080\x06\x02\x01\x07\x02\x01\x0e', 'sequence of set optional sequence encoded incorrectly')


   def defaultSeqTest(self):
      'checking coding of default sequence object'
      seq = POW.pkix.Sequence([POW.pkix.Integer()], 0, 'MAMCAQc=\n')
      try:
         seq.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(seq.toString() == '', 'unset default sequence encoded incorrectly')
      seq.fromString('')
      self.failUnless(seq.toString() == '', 'unset default sequence encoded incorrectly')
      values = (64,)
      seq.set( values )
      self.failUnless(seq.toString() == '0\x03\x02\x01@', 'set default sequence encoded incorrectly')
      seq.reset()
      seq.fromString('0\x03\x02\x01@')
      self.failUnless(seq.get() == (64,), 'set default sequence decoded incorrectly') 
      self.failUnless(seq.toString() == '0\x03\x02\x01@', 'set default sequence encoded incorrectly')

   def sequenceOfChoiceTest(self):
      'checking coding of sequence of choice objects'
      Time = lambda : POW.pkix.Choice({   'generalTime' : POW.pkix.GeneralizedTime(), 
                                          'utcTime' : POW.pkix.UtcTime() })
      seq = POW.pkix.Sequence([Time(), Time()])
      try:
         seq.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      now = POW.pkix.time2gen(1031669280.1208529)
      then = POW.pkix.time2gen(1031669280.1208529 + 60*60*24*365*12)
      seq.set( (('generalTime',now),('generalTime',then)) )
      self.failUnless(seq.get() == (('generalTime', '20020910144800Z'), ('generalTime', '20140907144800Z')),
                  'sequence of choice encoded incorrectly')
      self.failUnless(seq.toString() == '0"\x18\x0f20020910144800Z\x18\x0f20140907144800Z',
                  'sequence of choice encoded incorrectly')
      self.failUnless(seq.get() == (('generalTime', '20020910144800Z'), ('generalTime', '20140907144800Z')),
                  'sequence of choice decoded incorrectly')


   def seqOfDefaultSeqTest(self):
      'checking coding of sequence of default sequence object'
      seq = POW.pkix.Sequence([ POW.pkix.Sequence([POW.pkix.Integer()], 0, 'MAMCAQc=\n') ] )
      try:
         seq.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(seq.toString() == '0\x00', 'unset sequence of default sequence encoded incorrectly')
      seq.fromString('0\x00')
      values = ((128,),)
      seq.set( values )
      self.failUnless(seq.toString() == '0\x060\x04\x02\x02\x00\x80', 'set sequence of default sequence encoded incorrectly')
      seq.fromString(seq.toString())
      self.failUnless(seq.toString() == '0\x060\x04\x02\x02\x00\x80', 'set sequence of default sequence encoded incorrectly')
      self.failUnless(seq.get() == ((128,),), 'set sequence of default sequence decoded incorrectly') 
      seq.reset()
      seq.fromString('0\x00')
      self.failUnless(seq.get() == ((7,),), 'default of sequence of default sequence decoded incorrectly') 

   def sequenceOfSimpleTest(self):
      'checking coding of basic and empty sequenceOf object'
      sqo = POW.pkix.SequenceOf(POW.pkix.Integer)
      derval = sqo.toString()
      self.failUnless(sqo.toString() == '0\x00', 'empty sequenceOf encoded incorrectly')
      sqo.fromString('0\x00')
      self.failUnless(sqo.toString() == '0\x00', 'empty sequenceOf encoded incorrectly')
      sqo.set( (1,2,3,4) )
      sqo.fromString(derval)
      self.failUnless(sqo.get() == (), 'empty sequenceOf decoded incorrectly')
      sqo.set( (1,2,3,4) )
      self.failUnless(sqo.toString() == '0\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04', 'populated sequenceOf encoded incorrectly')
      sqo.reset()
      sqo.fromString('0\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04')
      self.failUnless(sqo.toString() == '0\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04', 'populated sequenceOf encoded incorrectly')
      self.failUnless(sqo.get() == (1,2,3,4), 'populated sequenceOf decoded incorrectly')

   def defaultSequenceOfTest(self):
      'checking coding of default sequenceOf object'
      sqo = POW.pkix.SequenceOf(POW.pkix.Integer,0,'MAwCAQECAQICAQMCAQQ=\n')
      try:
         sqo.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(sqo.toString() == '', 'unset default sequenceOf encoded incorrectly')
      sqo.set(())
      sqo.fromString('')
      self.failUnless(sqo.toString() == '', 'unset default sequenceOf encoded incorrectly')
      sqo.fromString(sqo.toString())
      self.failUnless(sqo.get() == (1,2,3,4), 'default sequenceOf decoded incorrectly')
      sqo.set((24,48) )
      self.failUnless(sqo.toString() == '0\x06\x02\x01\x18\x02\x010', 'populated default sequenceOf encoded incorrectly')
      sqo.reset()
      sqo.fromString('0\x06\x02\x01\x18\x02\x010')
      self.failUnless(sqo.get() == (24,48), 'populated default sequenceOf decoded incorrectly')
      self.failUnless(sqo.toString() == '0\x06\x02\x01\x18\x02\x010', 'populated default sequenceOf encoded incorrectly')

   def sequenceOfDefaultSequenceOfTest(self):
      'checking coding of sequence of default sequenceOf object'
      seq = POW.pkix.Sequence([ POW.pkix.SequenceOf(POW.pkix.Integer,0,'MAwCAQECAQICAQMCAQQ=\n') ])
      try:
         seq.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(seq.toString() == '0\x00', 'unset sequence of default sequenceOf encoded incorrectly')
      derval = seq.toString()
      seq.set( ((),) )
      seq.fromString(derval)
      self.failUnless(seq.get() == ((1,2,3,4),), 'sequence of default sequenceOf decoded incorrectly')
      seq.set( ((24,48),) )
      self.failUnless(seq.toString() == '0\x080\x06\x02\x01\x18\x02\x010', 'populated sequence of default sequenceOf encoded incorrectly')
      seq.reset()
      seq.fromString('0\x080\x06\x02\x01\x18\x02\x010')
      self.failUnless(seq.get() == ((24,48),), 'populated sequence of default sequenceOf decoded incorrectly')
      self.failUnless(seq.toString() == '0\x080\x06\x02\x01\x18\x02\x010', 'populated sequence of default sequenceOf encoded incorrectly')

   def optionalSequenceOfTest(self):
      'checking coding of optional sequenceOf object'
      sqo = POW.pkix.SequenceOf(POW.pkix.Integer,1)
      try:
         sqo.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(sqo.toString() == '', 'unset optional sequenceOf encoded incorrectly')
      sqo.set((24,48) )
      self.failUnless(sqo.toString() == '0\x06\x02\x01\x18\x02\x010', 'set optional sequenceOf encoded incorrectly')
      sqo.reset()
      sqo.fromString('0\x06\x02\x01\x18\x02\x010')
      self.failUnless(sqo.get() == (24,48), 'set optional sequenceOf decoded incorrectly')
      self.failUnless(sqo.toString() == '0\x06\x02\x01\x18\x02\x010', 'set optional sequenceOf encoded incorrectly')

   def sequenceOfOptionalSequenceOfTest(self):
      'checking coding of sequence of optional sequenceOf object'
      seq = POW.pkix.Sequence([ POW.pkix.SequenceOf(POW.pkix.Integer,1) ])
      try:
         seq.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(seq.toString() == '0\x00', 'unset sequence of optional sequenceOf encoded incorrectly')
      seq.set( ((1,2,3,4),) )
      self.failUnless(seq.toString() == '0\x0e0\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04', 
                              'populated sequence of optional sequenceOf encoded incorrectly')
      seq.reset()
      seq.fromString('0\x0e0\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04')
      self.failUnless(seq.get() == ((1,2,3,4),), 'populated sequence of optional sequenceOf decoded incorrectly')

   def basicExplicitTest(self):
      'checking coding of basic explicit object'
      exp = POW.pkix.Explicit( POW.pkix.CLASS_CONTEXT, POW.pkix.FORM_CONSTRUCTED, 0, POW.pkix.Integer() )
      try:
         exp.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      exp.set(1)
      self.failUnless(exp.toString() == '\xa0\x03\x02\x01\x01', 'set explicit integer encoded incorrectly')
      exp.reset()
      exp.fromString('\xa0\x03\x02\x01\x01')
      self.failUnless(exp.toString() == '\xa0\x03\x02\x01\x01', 'set explicit integer encoded incorrectly')
      self.failUnless(exp.get() == 1, 'set explicit integer decoded incorrectly')

   def defaultExplicitTest(self):
      'checking coding of default explicit object'
      exp = POW.pkix.Explicit( POW.pkix.CLASS_CONTEXT, POW.pkix.FORM_CONSTRUCTED, 0, POW.pkix.Integer(), 0, 'oAMCAQE=\n' )
      try:
         exp.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(exp.toString() == '', 'unset default epxlicit integer encoded incorrectly')
      exp.set(14)
      self.failUnless(exp.toString() == '\xa0\x03\x02\x01\x0e', 'set explicit integer encoded incorrectly')
      exp.reset()
      exp.fromString('\xa0\x03\x02\x01\x0e')
      self.failUnless(exp.get() == 14, 'set explicit integer decoded incorrectly')
      self.failUnless(exp.toString() == '\xa0\x03\x02\x01\x0e', 'set explicit integer encoded incorrectly')

   def optionalExplicitTest(self):
      'checking coding of optional explicit object'
      exp = POW.pkix.Explicit( POW.pkix.CLASS_CONTEXT, POW.pkix.FORM_CONSTRUCTED, 0, POW.pkix.Integer(), 1 )
      try:
         exp.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(exp.toString() == '', 'unset default epxlicit integer encoded incorrectly')
      exp.set(14)
      self.failUnless(exp.toString() == '\xa0\x03\x02\x01\x0e', 'set explicit integer encoded incorrectly')
      exp.reset()
      exp.fromString('\xa0\x03\x02\x01\x0e')
      self.failUnless(exp.get() == 14, 'set explicit integer decoded incorrectly')
      self.failUnless(exp.toString() == '\xa0\x03\x02\x01\x0e', 'set explicit integer encoded incorrectly')

   def basicChoiceTest(self):
      'checking coding of basic choice object'
      chint = POW.pkix.Integer()
      chstring = POW.pkix.OctetString()
      chbool = POW.pkix.Boolean()
      choices = { 'i' :  chint,
                  's' :  chstring,
                  'b' :  chbool }

      ch = POW.pkix.Choice(choices)
      try:
         ch.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      ch.set(('i',7))
      self.failUnless(ch.toString() == '\x02\x01\x07', 'set integer choice encoded incorrectly')
      ch.set(('s','Hello World'))
      self.failUnless(ch.toString() == '\x04\x0bHello World', 'set octet string choice encoded incorrectly')
      ch.set(('b',1))
      self.failUnless(ch.toString() == '\x01\x01\xff', 'set boolean choice encoded incorrectly')
      
      ch.fromString('\x02\x01\x07')
      self.failUnless(ch.get() == ('i',7), 'set integer choice decoded incorrectly')
      ch.fromString('\x04\x0bHello World')
      self.failUnless(ch.get() == ('s','Hello World'), 'set octet string choice decoded incorrectly')
      ch.fromString('\x01\x01\xff')
      self.failUnless(ch.get() == ('b',1), 'set integer boolean decoded incorrectly')

   def defaultChoiceTest(self):
      'checking coding of default choice object'
      chint = POW.pkix.Integer()
      chstring = POW.pkix.OctetString()
      chbool = POW.pkix.Boolean()
      choices = { 'i' :  chint,
                  's' :  chstring,
                  'b' :  chbool }

      ch = POW.pkix.Choice(choices,0,'AQH/\n')
      try:
         ch.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(ch.toString() == '', 'unset default choice encoded incorrectly')
      ch.set(('i',7))
      self.failUnless(ch.toString() == '\x02\x01\x07', 'set integer choice encoded incorrectly')
      ch.set(('s','Hello World'))
      self.failUnless(ch.toString() == '\x04\x0bHello World', 'set octet string choice encoded incorrectly')
      
      ch.fromString('\x02\x01\x07')
      self.failUnless(ch.get() == ('i',7), 'set integer choice decoded incorrectly')
      ch.fromString('\x04\x0bHello World')
      self.failUnless(ch.get() == ('s','Hello World'), 'set octet string choice decoded incorrectly')
      ch.fromString('')
      self.failUnless(ch.get() == ('b',1), 'set integer boolean decoded incorrectly')

   def optionalChoiceTest(self):
      'checking coding of optional choice object'
      chint = POW.pkix.Integer()
      chstring = POW.pkix.OctetString()
      chbool = POW.pkix.Boolean()
      choices = { 'i' :  chint,
                  's' :  chstring,
                  'b' :  chbool }

      ch = POW.pkix.Choice(choices,1)
      try:
         ch.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(ch.toString() == '', 'unset choice encoded incorrectly')
      ch.set(('i',7))
      self.failUnless(ch.toString() == '\x02\x01\x07', 'set integer choice encoded incorrectly')
      ch.set(('s','Hello World'))
      self.failUnless(ch.toString() == '\x04\x0bHello World', 'set octet string choice encoded incorrectly')
      ch.set(('b',1))
      self.failUnless(ch.toString() == '\x01\x01\xff', 'set boolean choice encoded incorrectly')
      
      ch.fromString('')
      self.failUnless(ch.get() == None, 'unset choice decoded incorrectly')
      ch.fromString('\x02\x01\x07')
      self.failUnless(ch.get() == ('i',7), 'set integer choice decoded incorrectly')
      ch.fromString('\x04\x0bHello World')
      self.failUnless(ch.get() == ('s','Hello World'), 'set octet string choice decoded incorrectly')
      ch.fromString('\x01\x01\xff')
      self.failUnless(ch.get() == ('b',1), 'set integer boolean decoded incorrectly')

   def choiceWithDefaultElementTest(self):
      'checking coding of choice object with default choice'
      chint = POW.pkix.Integer()
      chstring = POW.pkix.OctetString(0,'BAtIZWxsbyBXb3JsZA==\n')
      chbool = POW.pkix.Boolean()
      choices = { 'i' :  chint,
                  's' :  chstring,
                  'b' :  chbool }

      ch = POW.pkix.Choice(choices)
      try:
         ch.toString()
      except:
         self.fail('attempting to write this should not have raised and exception')
         pass
      self.failUnless(ch.get() == ('s','Hello World'), 'set octet string choice decoded incorrectly')
      ch.set(('i',7))
      self.failUnless(ch.toString() == '\x02\x01\x07', 'set integer choice encoded incorrectly')
      ch.set(('s','Hello World'))
      self.failUnless(ch.toString() == '', 'set octet string choice encoded incorrectly')
      ch.set(('b',1))
      self.failUnless(ch.toString() == '\x01\x01\xff', 'set boolean choice encoded incorrectly')
      
      ch.fromString('\x02\x01\x07')
      self.failUnless(ch.get() == ('i',7), 'set integer choice decoded incorrectly')
      ch.fromString('\x04\x0bHello World')
      self.failUnless(ch.get() == ('s','Hello World'), 'set octet string choice decoded incorrectly')
      ch.fromString('\x01\x01\xff')
      self.failUnless(ch.get() == ('b',1), 'set integer boolean decoded incorrectly')

class PkixTestCase(unittest.TestCase):
   'a set of tests to check codings of x509v3 objects'

   def confirmvalues(self, os, ns):
      for i in range( len(os) ):
         if os[i] != ns[i]:
            sys.stderr.write( '%i is faulty!\n' % i )
            sys.stderr.write( `os[i]`+'\n' )
            sys.stderr.write( `ns[i]`+'\n' )
            if isinstance(os[i], types.TupleType):
               self.confvalue(os[i], ns[i])
         else:
            print '%i is ok!' % i

   def validityTest(self):
      'checking coding of validity object'
      v = POW.pkix.Validity()
      try:
         v.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      now = POW.pkix.time2gen(1031669280.1208529)
      v.set( (('generalTime', now),('generalTime', now)) )
      self.failUnless(v.toString() == '0"\x18\x0f20020910144800Z\x18\x0f20020910144800Z', 'set validity encoded incorrectly')
      v.fromString('0"\x18\x0f20020910144800Z\x18\x0f20020910144800Z')
      self.failUnless(v.get() == (('generalTime', now), ('generalTime', now)), 'set validity encoded incorrectly')
      self.failUnless(v.toString() == '0"\x18\x0f20020910144800Z\x18\x0f20020910144800Z', 'set validity encoded incorrectly')

      now = POW.pkix.time2utc(1031669280.1208529)
      v.set( (('utcTime', now),('utcTime', now)) )
      self.failUnless(v.toString() == '0\x1e\x17\r020910144800Z\x17\r020910144800Z', 'set validity encoded incorrectly')
      v.fromString('0\x1e\x17\r020910144800Z\x17\r020910144800Z')
      self.failUnless(v.get() == (('utcTime', now), ('utcTime', now)), 'set validity encoded incorrectly')
      self.failUnless(v.toString() == '0\x1e\x17\r020910144800Z\x17\r020910144800Z', 'set validity encoded incorrectly')

   def directoryStringTest(self):
      'checking coding of directoryString object'
      d = POW.pkix.DirectoryString()
      try:
         d.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass

      d.set( ('teletexString', 'Hello World') )      
      derval = '\x14\x0bHello World'
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      d.fromString(derval)
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      self.failUnless(d.get() == ('teletexString', 'Hello World'), 'set directoryString encoded incorrectly')

      d.set( ('printableString', 'Hello World') )
      derval = '\x13\x0bHello World'
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      d.fromString(derval)
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      self.failUnless(d.get() == ('printableString', 'Hello World'), 'set directoryString encoded incorrectly')

      d.set( ('universalString', 'Hello World') )
      derval = '\x1c\x0bHello World'
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      d.fromString(derval)
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      self.failUnless(d.get() == ('universalString', 'Hello World'), 'set directoryString encoded incorrectly')

      d.set( ('bmpString', 'Hello World') )
      derval = '\x1e\x0bHello World'
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      d.fromString(derval)
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      self.failUnless(d.get() == ('bmpString', 'Hello World'), 'set directoryString encoded incorrectly')

      d.set( ('utf8String', 'Hello World') )
      derval = '\x0c\x0bHello World'
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      d.fromString(derval)
      self.failUnless(d.toString() == derval, 'set directoryString encoded incorrectly')
      self.failUnless(d.get() == ('utf8String', 'Hello World'), 'set directoryString encoded incorrectly')

   def attributeTypeAndValueTest(self):
      'checking coding of attributeTypeAndValueTest object'
      av = POW.pkix.AttributeTypeAndValue()
      try:
         av.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      av.set( (o2i('commonName'), None ) )
      try:
         av.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass
      av.set( (o2i('commonName'), ('utf8String', None) ) )
      try:
         av.toString()
         self.fail('attempting to write this should have raised and exception')
      except:
         pass

      av.set( (o2i('commonName'), ('utf8String', u'Peter Shannon') ) )
      derval = '0\x14\x06\x03U\x04\x03\x0c\rPeter Shannon'
      self.failUnless(av.toString() == derval, 'set attributeTypeAndValue encoded incorrectly')
      av.fromString(derval)
      self.failUnless(av.toString() == derval, 'set attributeTypeAndValue encoded incorrectly')
      self.failUnless(av.get() == (o2i('commonName'), ('utf8String', u'Peter Shannon')), 'set attributeTypeAndValue encoded incorrectly')


   def x509v2Test(self):
      'checking coding of x509v2 object'
      cipher = ciphers.getCipher('client')
      rsa = cipher[1]

      old = POW.pkix.Certificate()
      old.setVersion(1)
      old.setSerial(5)

      name = ( (( o2i('countryName'), ('printableString', 'GB') ),), 
               (( o2i('stateOrProvinceName'), ('printableString', 'Hertfordshire') ),), 
               (( o2i('organizationName'), ('printableString', 'The House') ),),
               (( o2i('commonName'), ('printableString', 'Client') ),) ) 

      old.setIssuer(name)
      old.setSubject(name)

      now = ('generalTime', POW.pkix.time2gen( time.time() ) )
      then = ('generalTime', POW.pkix.time2gen(time.time() + 60*60*24*365*12) )
      old.setNotBefore(now)
      old.setNotAfter(then)
      old.setIssuerUniqueID((1,0,1,0))
      old.setSubjectUniqueID((1,0,0,1))
      old.sign(rsa, POW.MD5_DIGEST)

      new = POW.pkix.Certificate()
      new.fromString( old.toString() )
      self.failUnless( new.getVersion() == 1, 'version was not presereved correctly')
      self.failUnless( new.getSerial() == 5, 'serial was not presereved correctly')
      self.failUnless( new.getNotBefore() == now, 'notBefore was not presereved correctly')
      self.failUnless( new.getNotAfter() == then, 'notAfter was not presereved correctly')
      self.failUnless( new.getIssuer() == name, 'issuerName was not presereved correctly')
      self.failUnless( new.getSubject() == name, 'subjectName was not presereved correctly')
      self.failUnless( new.getIssuerUniqueID() == (1,0,1,0), 'issuerUniqueId was not presereved correctly')
      self.failUnless( new.getSubjectUniqueID() == (1,0,0,1), 'subjectUniqueId was not presereved correctly')
      self.failUnless( new.verify(rsa), 'signed text was not verified')

#      os = old.get()
#      ns = new.get()
#      self.confirmvalues(os,ns)


   def x509v3Test(self):
      'checking coding of x509v3 object'

      now = POW.pkix.time2gen( time.time() )
      then = POW.pkix.time2gen(time.time() + 60*60*24*365*12)
      cipher = ciphers.getCipher('client')
      rsa = cipher[1]

      policy = ( 
                  ( o2i('id-cti-ets-proofOfReceipt'), (
                     (o2i('cps'),     ('cPSuri', 'http://www.p-s.org.uk/policies/policy1')), 
                     (o2i('unotice'), ('userNotice', ((('visibleString', 'The House'),(1,2,3)), ('visibleString', 'We guarentee nothing'))  )),
                  )),
                  ( o2i('id-cti-ets-proofOfOrigin'), (
                     (o2i('cps'), ('cPSuri', 'http://www.p-s.org.uk/policies/policy2')), 
                  ))
               )

      n1 = ('directoryName',  (  (( o2i('countryName'), ('printableString', 'UK') ),), 
                                 (( o2i('stateOrProvinceName'), ('printableString', 'Herts') ),), 
                                 (( o2i('organizationName'), ('printableString', 'The House') ),),
                                 (( o2i('commonName'), ('printableString', 'Shannon Works') ),) ) ) 

      n2 = ('rfc822Name', 'peter_shannon@yahoo.com')
      n3 = ('uri', 'http://www.p-s.org.uk') 
      n4 = ('iPAddress', POW.pkix.ip42oct(192,168,100,51)) 

      points = ( ( ('fullName',(n1, n4)), (1,1,1,1,1), (n1,) ), )

      authdigest = POW.Digest( POW.SHA1_DIGEST )
      authdigest.update(rsa.derWrite(POW.RSA_PUBLIC_KEY))
      keyHash = authdigest.digest()
      
      myExtensions = (
                        ( o2i('privateKeyUsagePeriod'),0, (now, then)),
                        ( o2i('keyUsage'),0, (1,1)),
                        ( o2i('basicConstraints'),0, (0,None)),
                        ( o2i('subjectKeyIdentifier'),0, keyHash),
                        ( o2i('certificatePolicies'),0, policy ),
                        ( o2i('subjectAltName'),0, (n2,)),
                        ( o2i('issuerAltName'),0, (n1,n2,n3,n4)),
                        ( o2i('authorityKeyIdentifier'),0, (keyHash, (), None) ),
                        ( o2i('cRLDistributionPoints'),0, points ),
                     )

      old = POW.pkix.Certificate()
      old.setVersion(2)
      old.setSerial(5)

      name =   (
         (( o2i('commonName'), ('printableString', 'Peter Shannon') ),),
               )

      old.setIssuer(name)
      old.setSubject(name)

      old.setNotBefore( ('generalTime',  now) )
      old.setNotAfter( ( 'generalTime',  then) )

      old.setExtensions( myExtensions )
      old.sign(rsa, POW.MD5_DIGEST)

      new = POW.pkix.Certificate()
      new.fromString( old.toString() )

      extns = new.getExtensions()

#      ns = new.getExtensions()
#      self.confirmvalues(myExtensions,ns)

      self.failUnless( new.getVersion() == 2, 'version was not presereved correctly')
      self.failUnless( new.getSerial() == 5, 'serial was not presereved correctly')
      self.failUnless( new.getIssuer() == name, 'issuerName was not presereved correctly')
      self.failUnless( new.getSubject() == name, 'subjectName was not presereved correctly')
      self.failUnless( new.getNotBefore()[1] == now, 'notBefore was not presereved correctly')
      self.failUnless( new.getNotAfter()[1] == then, 'notAfter was not presereved correctly')
      self.failUnless( new.getExtensions() == myExtensions, 'extensions were not presereved correctly')
      self.failUnless( new.verify(rsa), 'signed text was not verified')

   def basicConstraintsTest(self):
      'checking coding of basicConstraints'
      for val in [(0,0),(0,None), (1,None), (0,1),(0,2),(1,0),(1,1),(1,2)]:
         self.failUnless( checkValue(POW.pkix.BasicConstraints, val), '%s was not presereved correctly' % `val`)

   def generalNameTest(self):
      'checking coding of subjectAltName'
      values = [
         (('directoryName', (    (( o2i('countryName'), ('printableString', 'UK')               ),), 
                                 (( o2i('stateOrProvinceName'), ('printableString', 'Herts')    ),), 
                                 (( o2i('organizationName'), ('printableString', 'The House')   ),),
                                 (( o2i('commonName'), ('printableString', 'Shannon Works')     ),),   )
         ),),
         (('rfc822Name', 'peter_shannon@yahoo.com'),),
         (('uri', 'http://www.p-s.org.uk'),),
         (('iPAddress', POW.pkix.ip42oct(192,168,100,51)),),
         (('registeredId', o2i('countryName')),),
         (),
               ]
      for val in values:
         self.failUnless( checkValue(POW.pkix.GeneralNames, val), '%s was not presereved correctly' % `val`)

   def crlv1Test(self):
      'checking coding of CRLv1 object'
      now = POW.pkix.time2gen( time.time() )
      then = POW.pkix.time2gen(time.time() + 60*60*24*365*12)
      cipher = ciphers.getCipher('client')
      rsa = cipher[1]

      old = POW.pkix.CertificateList()
      old.setThisUpdate( ('generalTime', now ) )

      name = ( (( o2i('countryName'), ('printableString', 'GB') ),), 
               (( o2i('stateOrProvinceName'), ('printableString', 'Hertfordshire') ),), 
               (( o2i('organizationName'), ('printableString', 'The House') ),),
               (( o2i('commonName'), ('printableString', 'Client') ),) ) 

      myRevocations = (
                        (1, ('generalTime', now), ()),
                        (2, ('generalTime', now), ()),
                        (3, ('generalTime', now), (( o2i('cRLReason'), 0, 1),)) 
                      ) 

      old.setIssuer(name)
      old.setRevokedCertificates( myRevocations )

      old.sign(rsa, POW.MD5_DIGEST)

      new = POW.pkix.CertificateList()
      new.fromString( old.toString() )
      self.failUnless( new.getVersion() == None, 'version was not presereved correctly')
      self.failUnless( new.getThisUpdate()[1] == now, 'thisUpdate was not presereved correctly')
      self.failUnless( new.getIssuer() == name, 'issuerName was not presereved correctly')
      self.failUnless( new.getRevokedCertificates() == myRevocations, 'revokedCerticates was not presereved correctly')
      self.failUnless( new.verify(rsa), 'signed envelope was not presereved correctly')


class ExtensionsTestCase(unittest.TestCase):
   'Extentions Tests'

   def extensionManipulationTest(self):
      'Extensions manipulation for X509 object tests'
      sc = certs.getCert('server')
      basic = POW.pkix.BasicConstraints()
      basic.set([1,5]) 
      sc.addExtension( 'basicConstraints', 0, basic.toString() )
      sc.addExtension( 'basicConstraints', 0, basic.toString() )
      sc.addExtension( 'basicConstraints', 0, basic.toString() )
      self.failUnless( sc.countExtensions() == 3, 'cert should have 3 any extensions')
      sc.clearExtensions()
      self.failUnless( sc.countExtensions() == 0, 'cert should not have any extensions')
      sc.addExtension( 'basicConstraints', 0, basic.toString() )
      basic.set([0,1]) 
      sc.addExtension( 'basicConstraints', 0, basic.toString() )
      basic = POW.pkix.BasicConstraints()
      basic.fromString( sc.getExtension(1)[2] )
      self.failUnless( basic.get() == (0,1), 'incorrect extension handling ')

   def basicConstraintTest(self):
      'Basic constraints tests'
      serverCert = certs.getCert('server')
      basic = POW.pkix.BasicConstraints()
      basic.set([1,5]) 
      serverCert.addExtension( 'basicConstraints', 0, basic.toString() )
      basic = POW.pkix.BasicConstraints()
      basic.fromString( serverCert.getExtension(0)[2] )
      values = basic.get()
      self.failUnless( values[0] == 1, 'ca value should be true')
      self.failUnless( values[1] == 5, 'pathlen values should be 5')

   def privateKeyUsagePeriodTest(self):
      'Private key usage period tests'
      serverCert = certs.getCert('server')
      period = POW.pkix.PrivateKeyUsagePeriod()
      t1 = POW.pkix.time2gen( time.time() )
      t2 = POW.pkix.time2gen(time.time() + 60*60*24*365 )
      period.set([t1,t2]) 
      serverCert.addExtension( 'privateKeyUsagePeriod', 0, period.toString() )
      period = POW.pkix.PrivateKeyUsagePeriod()
      period.fromString( serverCert.getExtension(0)[2] )
      values = period.get()
      self.failUnless( values == (t1,t2), 'private key usage period is incorrect')

   def keyUsageTest(self):
      'privateKeyUsage tests'
      serverCert = certs.getCert('server')
      usage = POW.pkix.KeyUsage()
      usage.set([1,1]) 
      serverCert.addExtension( 'keyUsage', 0, usage.toString() )
      usage = POW.pkix.KeyUsage()
      usage.fromString( serverCert.getExtension(0)[2] )
      values = usage.get()
      self.failUnless( values == (1,1), 'bit pattern is incorrect')

   def issuerAltNameTest(self):
      'Issuer Alt Name tests'
      n1 = ('directoryName',  (  (( o2i('countryName'), ('printableString', 'UK') ),), 
                                 (( o2i('stateOrProvinceName'), ('printableString', 'Herts') ),), 
                                 (( o2i('organizationName'), ('printableString', 'The House') ),),
                                 (( o2i('commonName'), ('printableString', 'Shannon Works') ),) ) ) 

      n2 = ('rfc822Name', 'peter_shannon@yahoo.com')
      n3 = ('uri', 'http://www.p-s.org.uk') 
      n4 = ('iPAddress', POW.pkix.ip42oct(192,168,100,51)) 

      serverCert = certs.getCert('server')
      issuer = POW.pkix.IssuerAltName()
      issuer.set([n1,n2,n3,n4]) 
      serverCert.addExtension( 'issuerAltName', 0, issuer.toString() )
      issuer = POW.pkix.IssuerAltName()
      issuer.fromString( serverCert.getExtension(0)[2] )
      values = issuer.get()
      self.failUnless( values == (n1,n2,n3,n4), 'generalNames are incorrect')

   def subjectAltNameTest(self):
      'Subject Alt Name tests'
      n1 = ('directoryName',  (  (( o2i('countryName'), ('printableString', 'UK') ),), 
                                 (( o2i('stateOrProvinceName'), ('printableString', 'Herts') ),), 
                                 (( o2i('organizationName'), ('printableString', 'The House') ),),
                                 (( o2i('commonName'), ('printableString', 'Shannon Works') ),) ) ) 

      n2 = ('rfc822Name', 'peter_shannon@yahoo.com')
      n3 = ('uri', 'http://www.p-s.org.uk') 
      n4 = ('iPAddress', POW.pkix.ip42oct(192,168,100,51)) 

      serverCert = certs.getCert('server')
      subject = POW.pkix.SubjectAltName()
      subject.set([n1,n2,n3,n4]) 
      serverCert.addExtension( 'subjectAltName', 0, subject.toString() )
      subject = POW.pkix.SubjectAltName()
      subject.fromString( serverCert.getExtension(0)[2] )
      values = subject.get()
      self.failUnless( values == (n1,n2,n3,n4), 'generalNames are incorrect')


   def certPolicyTest(self):
      'Certificate Policies tests'
      policies=( 
                  ( o2i('id-cti-ets-proofOfReceipt'), (
                     (o2i('cps'),     ('cPSuri', 'http://www.p-s.org.uk/policies/ps1')), 
                     (o2i('unotice'), ('userNotice', ((('visibleString', 'The House'),(1,2,3)), ('visibleString', 'We guarentee nothing'))  )),
                  )),
                  ( o2i('id-cti-ets-proofOfOrigin'), (
                     (o2i('cps'), ('cPSuri', 'http://www.p-s.org.uk/policies/p2')), 
                  ))
               )

      serverCert = certs.getCert('server')
      policy = POW.pkix.CertificatePolicies()
      policy.set(policies) 
      serverCert.addExtension( 'certificatePolicies', 0, policy.toString() )
      policy = POW.pkix.CertificatePolicies()
      policy.fromString( serverCert.getExtension(0)[2] )
      values = policy.get()
      self.failUnless( values == policies, 'policies are incorrect')



#--------------- Hash test case ---------------#

class HashTestCase(unittest.TestCase):
   'Hash algorithm tests'

   plainText = 'My extremely silly pass phrase!'

   def _symmetricGeneralTest(self, type, expected=None):
      digest = POW.Digest( type ) 
      digest.update( self.plainText )
      b64Text = base64.encodestring( digest.digest() )
      self.failUnlessEqual( b64Text, expected, 'Digest result incorrect' )

   def testMd2(self):
      'Generate and check MD2 hash'
      self._symmetricGeneralTest( POW.MD2_DIGEST, 'O9VUpKqYAHkCgPyAkclL8g==\n' )

   def testMd5(self):
      'Generate and check MD5 hash'
      self._symmetricGeneralTest( POW.MD5_DIGEST, 'kzb1VPPjrYNNA0gwsoKsQw==\n' )

   def testSha(self):
      'Generate and check SHA hash'
      self._symmetricGeneralTest( POW.SHA_DIGEST, 'ptkIj1ilu9oFTFbP3A6o3KuJL+Q=\n')

   def testSha1(self):
      'Generate and check SHA1 hash'
      self._symmetricGeneralTest( POW.SHA1_DIGEST, '7zk06ujVcAWhzREYzY4s4lCw4WQ=\n' )

   def testRipemd160(self):
      'Generate and check RIPEMD160 hash'
      self._symmetricGeneralTest( POW.RIPEMD160_DIGEST, 'R+ve9PdUxqr45duMhG8CBQiahkU=\n' )

#--------------- Hash test case ---------------#
#--------------- Hmac test case ---------------#

class HmacTestCase(unittest.TestCase):
   'HMAC algorithm tests'

   plainText = 'My extremely silly pass phrase!'
   password = 'Puny pass word'

   def _symmetricGeneralTest(self, type, expected=None):
      hmac = POW.Hmac( type, self.password ) 
      hmac.update( self.plainText )
      b64Text = base64.encodestring( hmac.mac() )
      self.failUnlessEqual( b64Text, expected, 'HMAC result incorrect' )

   def testHmacMd2(self):
      'Generate and check MD2 HMAC'
      self._symmetricGeneralTest( POW.MD2_DIGEST, 'UgWmfru6kM68GFn3HMmbeg==\n' )

   def testHmacMd5(self):
      'Generate and check MD5 HMAC'
      self._symmetricGeneralTest( POW.MD5_DIGEST, '+l1oP2UbL0dW7L51lw2LSg==\n' )

   def testHmacSha(self):
      'Generate and check SHA HMAC'
      self._symmetricGeneralTest( POW.SHA_DIGEST, 'xuLEZcpj96p2Uo0/Ief1zjUdJdM=\n')

   def testHmacSha1(self):
      'Generate and check SHA1 HMAC'
      self._symmetricGeneralTest( POW.SHA1_DIGEST, 'nnT7qPYMHjJ46JXQWmR/Ap0XK2E=\n' )

   def testHmacRipemd160(self):
      'Generate and check RIPEMD160 HMAC'
      self._symmetricGeneralTest( POW.RIPEMD160_DIGEST, 'AeSjVffp5FPIBBtabpD/nwVDz/s=\n' )

#--------------- Hmac test case ---------------#
#--------------- Symmetric cipher test case ---------------#

class SymmetricTestCase(unittest.TestCase):
   'Symmetric algorithm tests'

   password = 'Hello :)'

   plainText = '''
# Basic system aliases that MUST be present.
postmaster:	root
mailer-daemon:	postmaster

# amavis
virusalert:	root

# General redirections for pseudo accounts in /etc/passwd.
administrator:	root
daemon:		root
lp:		root
news:		root
uucp:		root
games:		root
man:		root
at:		root
postgres:	root
mdom:		root
amanda:		root
ftp:		root
wwwrun:		root
squid:		root
msql:		root
gnats:		root
nobody:		root
'''

   plainText = 'Hello World'

   def _symmetricGeneralTest(self, type):
      symmetric = POW.Symmetric( type )
      symmetric.encryptInit( self.password )
      cipherText = symmetric.update( self.plainText ) + symmetric.final()
      symmetric.decryptInit( self.password )
      decipheredText = symmetric.update( cipherText ) + symmetric.final()
      self.failUnlessEqual( self.plainText, decipheredText, 'decrypted cipher text not equal to original text' )

   def testDES_ECB(self):
      'Generate and check DES_ECB encrypted text'
      self._symmetricGeneralTest( POW.DES_ECB )

   def testDES_EDE(self):
      'Generate and check DES_EDE encrypted text'
      self._symmetricGeneralTest( POW.DES_EDE )

   def testDES_EDE3(self):
      'Generate and check DES_EDE3 encrypted text'
      self._symmetricGeneralTest( POW.DES_EDE3 )

   def testDES_CFB(self):
      'Generate and check DES_CFB encrypted text'
      self._symmetricGeneralTest( POW.DES_ECB )

   def testDES_EDE_CFB(self):
      'Generate and check DES_EDE_CFB encrypted text'
      self._symmetricGeneralTest( POW.DES_EDE_CFB )

   def testDES_EDE3_CFB(self):
      'Generate and check DES_EDE3_CFB encrypted text'
      self._symmetricGeneralTest( POW.DES_EDE3_CFB )

   def testDES_OFB(self):
      'Generate and check DES_OFB encrypted text'
      self._symmetricGeneralTest( POW.DES_OFB )

   def testDES_EDE_OFB(self):
      'Generate and check DES_EDE_OFB encrypted text'
      self._symmetricGeneralTest( POW.DES_EDE_OFB )

   def testDES_EDE3_OFB(self):
      'Generate and check DES_EDE3_OFB encrypted text'
      self._symmetricGeneralTest( POW.DES_EDE3_OFB )

   def testDES_CBC(self):
      'Generate and check DES_CBC encrypted text'
      self._symmetricGeneralTest( POW.DES_CBC )

   def testDES_EDE_CBC(self):
      'Generate and check DES_EDE_CBC encrypted text'
      self._symmetricGeneralTest( POW.DES_EDE_CBC )

   def testDES_EDE3_CBC(self):
      'Generate and check DES_EDE3_CBC encrypted text'
      self._symmetricGeneralTest( POW.DES_EDE3_CBC )

   def testDESX_CBC(self):
      'Generate and check DESX_CBC encrypted text'
      self._symmetricGeneralTest( POW.DESX_CBC )

   def testRC4(self):
      'Generate and check RC4 encrypted text'
      self._symmetricGeneralTest( POW.RC4 )

   def testRC4_40(self):
      'Generate and check RC4_40 encrypted text'
      self._symmetricGeneralTest( POW.DES_EDE3_CBC )

   def testIDEA_ECB(self):
      'Generate and check IDEA_ECB encrypted text'
      self._symmetricGeneralTest( POW.IDEA_ECB )

   def testIDEA_CFB(self):
      'Generate and check IDEA_CFB encrypted text'
      self._symmetricGeneralTest( POW.IDEA_CFB )

   def testIDEA_OFB(self):
      'Generate and check IDEA_OFB encrypted text'
      self._symmetricGeneralTest( POW.IDEA_OFB )

   def testIDEA_CBC(self):
      'Generate and check IDEA_CBC encrypted text'
      self._symmetricGeneralTest( POW.IDEA_CBC )

   def testRC2_ECB(self):
      'Generate and check RC2_ECB encrypted text'
      self._symmetricGeneralTest( POW.RC2_ECB )

   def testRC2_CBC(self):
      'Generate and check RC2_CBC encrypted text'
      self._symmetricGeneralTest( POW.RC2_CBC )

   def testRC2_40_CBC(self):
      'Generate and check RC2_40_CBC encrypted text'
      self._symmetricGeneralTest( POW.RC2_40_CBC )

   def testRC2_CFB(self):
      'Generate and check RC2_CFB encrypted text'
      self._symmetricGeneralTest( POW.RC2_CFB )

   def testRC2_OFB(self):
      'Generate and check RC2_OFB encrypted text'
      self._symmetricGeneralTest( POW.RC2_OFB )

   def testBF_ECB(self):
      'Generate and check BF_ECB encrypted text'
      self._symmetricGeneralTest( POW.BF_ECB )

   def testBF_CBC(self):
      'Generate and check BF_CBC encrypted text'
      self._symmetricGeneralTest( POW.BF_CBC )

   def testBF_CFB(self):
      'Generate and check BF_CFB encrypted text'
      self._symmetricGeneralTest( POW.BF_CFB )

   def testBF_OFB(self):
      'Generate and check BF_OFB encrypted text'
      self._symmetricGeneralTest( POW.BF_OFB )

   def testCAST5_ECB(self):
      'Generate and check CAST5_ECB encrypted text'
      self._symmetricGeneralTest( POW.CAST5_ECB )

   def testCAST5_CBC(self):
      'Generate and check CAST5_CBC encrypted text'
      self._symmetricGeneralTest( POW.CAST5_CBC )

   def testCAST5_CFB(self):
      'Generate and check CAST5_CFB encrypted text'
      self._symmetricGeneralTest( POW.CAST5_CFB )

   def testCAST5_OFB(self):
      'Generate and check CAST5_OFB encrypted text'
      self._symmetricGeneralTest( POW.CAST5_OFB )

   def testRC5_32_12_16_CBC(self):
      'Generate and check CAST5_OFB encrypted text'
      self._symmetricGeneralTest( POW.CAST5_OFB )

   def testRC5_32_12_16_CFB(self):
      'Generate and check CAST5_OFB encrypted text'
      self._symmetricGeneralTest( POW.CAST5_OFB )

   def testRC5_32_12_16_ECB(self):
      'Generate and check CAST5_OFB encrypted text'
      self._symmetricGeneralTest( POW.CAST5_OFB )

   def testRC5_32_12_16_OFB(self):
      'Generate and check CAST5_OFB encrypted text'
      self._symmetricGeneralTest( POW.CAST5_OFB )

#--------------- Symmetric cipher test case ---------------#
#--------------- Asymmetric cipher test case ---------------#

class AsymmetricUtilities:

   keys = { 'client' : { 'priv' : 'working/key1Priv', 'pub' : 'working/key1Pub' },
            'server' : { 'priv' : 'working/key2Priv', 'pub' : 'working/key2Pub' },
            'ca'     : { 'priv' : 'working/key3Priv', 'pub' : 'working/key3Pub' },
            'ca2'    : { 'priv' : 'working/key4Priv', 'pub' : 'working/key4Pub' },
            'ca3'    : { 'priv' : 'working/key5Priv', 'pub' : 'working/key5Pub' },
            'server2': { 'priv' : 'working/key6Priv', 'pub' : 'working/key6Pub' }   }

   password = 'Silly password'

   def prepCiphers(self):
      for entity in self.keys.keys():
         self.makeCipher(entity)

   def unPrepCiphers(self):
      for entity in self.keys.keys():
         self.remCipher(entity)

   def getCipher(self, entry):
      privFile = open( self.keys[entry]['priv'] )
      pubFile = open( self.keys[entry]['pub'] )
      priv = POW.pemRead( POW.RSA_PRIVATE_KEY,privFile.read(),  self.password )
      pub = POW.pemRead( POW.RSA_PUBLIC_KEY, pubFile.read() )
      privFile.close()
      pubFile.close()
      return (pub, priv)
 
   def makeCipher(self, entry):
      cipher = POW.Asymmetric()
      privFile = open( self.keys[entry]['priv'], 'w' )
      pubFile = open( self.keys[entry]['pub'], 'w' )
      privFile.write( cipher.pemWrite( POW.RSA_PRIVATE_KEY, POW.DES_EDE3_CFB, self.password ) )
      pubFile.write( cipher.pemWrite( POW.RSA_PUBLIC_KEY ) )
      privFile.close()
      pubFile.close()

   def remCipher(self, entry):
      try: os.remove( self.keys[entry]['priv'] )
      except: pass
      try: os.remove( self.keys[entry]['pub'] )
      except: pass

class AsymmetricTestCase(unittest.TestCase):
   'Asymmetric algorithm tests'

   plainText = 'A little text to encrypt!'

   def testPemIo(self):
      'Read and write ciphers in PEM format'
      cipher = ciphers.getCipher('client')
      public = cipher[0]
      private = cipher[1]
      pub = public.pemWrite( POW.RSA_PUBLIC_KEY )
      public2 = POW.pemRead( POW.RSA_PUBLIC_KEY, pub )
      priv = private.pemWrite( POW.RSA_PRIVATE_KEY )
      private2 = POW.pemRead( POW.RSA_PRIVATE_KEY, priv )
      priv = private.pemWrite( POW.RSA_PRIVATE_KEY, POW.DES_EDE3_CFB, 'password' )
      private2 = POW.pemRead( POW.RSA_PRIVATE_KEY, priv, 'password' )
      cipherText = public2.publicEncrypt( self.plainText )
      deCiphered = private2.privateDecrypt( cipherText )
      self.failUnlessEqual( self.plainText, deCiphered )

   def testDerIo(self):
      'Read and write ciphers in DER format'
      cipher = ciphers.getCipher('client')
      publicKey = cipher[0]
      privateKey = cipher[1]
      pubDer = publicKey.derWrite( POW.RSA_PUBLIC_KEY )
      publicKey2 = POW.derRead( POW.RSA_PUBLIC_KEY, pubDer )
      privDer = privateKey.derWrite( POW.RSA_PRIVATE_KEY )
      privateKey2 = POW.derRead( POW.RSA_PRIVATE_KEY, privDer)
      cipherText = publicKey.publicEncrypt( self.plainText )
      deCiphered = privateKey.privateDecrypt( cipherText )
      self.failUnlessEqual( self.plainText, deCiphered )

   def testPublicEncrypt(self):
      'Encrypt text using public RSA cipher, decrypt and compare'
      cipher = ciphers.getCipher('client')
      public = cipher[0]
      private = cipher[1]
      cipherText = public.publicEncrypt( self.plainText )
      deCiphered = private.privateDecrypt( cipherText )
      self.failUnlessEqual( self.plainText, deCiphered )

   def testPrivateEncrypt(self):
      'Encrypt text using private RSA cipher, decrypt and compare'
      cipher = ciphers.getCipher('client')
      public = cipher[0]
      private = cipher[1]
      cipherText = private.privateEncrypt( self.plainText )
      deCiphered = public.publicDecrypt( cipherText )
      self.failUnlessEqual( self.plainText, deCiphered )

   def testSign(self):
      'Sign text using private RSA cipher and verify'
      cipher = ciphers.getCipher('client')
      public = cipher[0]
      private = cipher[1]
      digest = POW.Digest( POW.SHA1_DIGEST )
      digest.update( self.plainText )
      signedText = private.sign( digest.digest(), POW.SHA1_DIGEST )
      self.failUnless( public.verify( signedText, digest.digest(), POW.SHA1_DIGEST ) )

#--------------- Asymmetric cipher test case ---------------#
#--------------- X509 test case ---------------#

class X509Utilities:

   certs = {   'client' : 'working/cert1',
               'server' : 'working/cert2',
               'ca'     : 'working/cert3',    
               'ca2'    : 'working/cert4',
               'ca3'    : 'working/cert5',
               'server2': 'working/cert6'    }

   clientName = ( ('C', 'GB'), ('ST', 'Hertfordshire'),
                  ('O', 'The House'), ('CN', 'Client') )

   serverName = ( ('C', 'GB'), ('ST', 'Hertfordshire'),
                  ('O', 'The House'), ('CN', 'Server') )

   caName = (  ('C', 'GB'), ('ST', 'Hertfordshire'),
               ('O', 'The House'), ('CN', 'CA') )

   ca2Name = (  ('C', 'GB'), ('ST', 'Hertfordshire'),
               ('O', 'The House'), ('CN', 'CA2') )

   ca3Name = (  ('C', 'GB'), ('ST', 'Hertfordshire'),
               ('O', 'The House'), ('CN', 'CA3') )

   server2Name = (  ('C', 'GB'), ('ST', 'Hertfordshire'),
               ('O', 'The House'), ('CN', 'server2') )

   notBefore = POW.pkix.time2utc(1005960447)
   notAfter = POW.pkix.time2utc(1037496447)

   caSerial = 0
   serverSerial = 1
   clientSerial = 2
   ca2Serial = 3
   ca3Serial = 4
   server2Serial = 5

   def __init__(self):
      self.asymUtils = AsymmetricUtilities()
      self.asymUtils.prepCiphers()

   def prepCerts(self):
      for cert in self.certs.keys():
         self.makeCert(cert)

   def unPrepCerts(self):
      self.asymUtils.unPrepCiphers()
      for cert in self.certs.keys():
         self.remCert(cert)

   def getCert(self, entry):
      certFile = open( self.certs[entry] )
      cert = POW.pemRead( POW.X509_CERTIFICATE, certFile.read() )
      certFile.close()
      return cert
 
   def makeCert(self, entry):
      caCipher = self.asymUtils.getCipher('ca')
      ca2Cipher = self.asymUtils.getCipher('ca2')
      ca3Cipher = self.asymUtils.getCipher('ca3')
      cert = POW.X509()
      #cert.setVersion(2)

      if entry == 'server':
         serverCipher = self.asymUtils.getCipher('server')
         cert.setIssuer( self.caName )
         cert.setSubject( self.serverName )
         cert.setSerial( self.serverSerial )
         cert.setNotBefore( self.notBefore )
         cert.setNotAfter( self.notAfter )
         cert.setPublicKey( serverCipher[1] )
         cert.sign( caCipher[1] )

      elif entry == 'client':
         clientCipher = self.asymUtils.getCipher('client')
         cert.setIssuer( self.caName )
         cert.setSubject( self.clientName )
         cert.setSerial( self.clientSerial )
         cert.setNotBefore( self.notBefore )
         cert.setNotAfter( self.notAfter )
         cert.setPublicKey( clientCipher[0] )
         cert.sign( caCipher[1] )

      elif entry == 'ca':
         cert.setIssuer( self.caName )
         cert.setSubject( self.caName )
         cert.setSerial( self.caSerial )
         cert.setNotBefore( self.notBefore )
         cert.setNotAfter( self.notAfter )
         cert.setPublicKey( caCipher[0] )
         cert.sign( caCipher[1] )

      elif entry == 'ca2':
         cert.setIssuer( self.caName )
         cert.setSubject( self.ca2Name )
         cert.setSerial( self.ca2Serial )
         cert.setNotBefore( self.notBefore )
         cert.setNotAfter( self.notAfter )
         cert.setPublicKey( ca2Cipher[0] )
         cert.sign( caCipher[1] )

      elif entry == 'ca3':
         cert.setIssuer( self.ca2Name )
         cert.setSubject( self.ca3Name )
         cert.setSerial( self.ca3Serial )
         cert.setNotBefore( self.notBefore )
         cert.setNotAfter( self.notAfter )
         cert.setPublicKey( ca3Cipher[0] )
         cert.sign( ca2Cipher[1] )

      elif entry == 'server2':
         server2Cipher = self.asymUtils.getCipher('server2')
         cert.setIssuer( self.ca3Name )
         cert.setSubject( self.server2Name )
         cert.setSerial( self.server2Serial )
         cert.setNotBefore( self.notBefore )
         cert.setNotAfter( self.notAfter )
         cert.setPublicKey( server2Cipher[0] )
         cert.sign( ca3Cipher[1] )

      else:
         raise Exception, 'Entry should be ca, ca2, server, server2 or client!'

      certFile = open( self.certs[entry], 'w' )
      certFile.write( cert.pemWrite() )
      certFile.close()

   def remCert(self, entry):
      try: os.remove( self.certs[entry] )
      except: pass

class X509TestCase(unittest.TestCase):
   'X509 tests'

   def testPemIo(self):
      'Read and write certificate in PEM format'
      serverCert = certs.getCert('server')
      cert = serverCert.pemWrite()
      cert2 = POW.pemRead( POW.X509_CERTIFICATE, cert )
      serverCert.getIssuer()

   def testDerIo(self):
      'Read and write certificate in DER format'
      serverCert = certs.getCert('server')
      cert = serverCert.derWrite()
      cert2 = POW.derRead( POW.X509_CERTIFICATE, cert )
      serverCert.getIssuer()

   def testIssuer(self):
      'Check the issuer is correct for server cerficate'
      serverCert = certs.getCert('server')
      self.failUnlessEqual( certs.caName, serverCert.getIssuer() )

   def testSubject(self):
      'Check the subject is correct for server cerficate'
      serverCert = certs.getCert('server')
      self.failUnlessEqual( certs.serverName, serverCert.getSubject() )

   def testVersion(self):
      'Check version number is correct for server cerficate'
      serverCert = certs.getCert('server')
      self.failUnlessEqual( 1, serverCert.getSerial() )

   def testSerial(self):
      'Check serial number is correct for server cerficate'
      serverCert = certs.getCert('server')
      self.failUnlessEqual( certs.serverSerial, serverCert.getSerial() )

   def testNotBefore(self):
      'Check notBefore date is correct for server cerficate'
      serverCert = certs.getCert('server')
      self.failUnlessEqual( certs.notBefore, serverCert.getNotBefore() )

   def testNotAfter(self):
      'Check notAfter date is correct for server cerficate'
      serverCert = certs.getCert('server')
      self.failUnlessEqual( certs.notAfter, serverCert.getNotAfter() )

#--------------- X509 test case ---------------#
#--------------- X509 Store test case ---------------#

class X509StoreTestCase(unittest.TestCase):
   'X509 Store tests'

   def testVerify(self):
      'Verify server\'s certificate againtst CA certificate'
      caCert = certs.getCert('ca')
      serverCert = certs.getCert('server')

      store = POW.X509Store()
      store.addTrust( caCert )
      self.failUnless( store.verify( serverCert ) )

   def testVerifyChain(self):
      'Verify chain of certificate againtst CA certificate'
      caCert = certs.getCert('ca')
      ca2Cert = certs.getCert('ca2')
      ca3Cert = certs.getCert('ca3')
      server2Cert = certs.getCert('server2')

      store = POW.X509Store()
      store.addTrust( caCert )
      self.failUnless( store.verifyChain( server2Cert, [ca3Cert, ca2Cert ])  )


#--------------- X509 Store test case ---------------#
#--------------- X509 Revoked test case ---------------#

class X509RevokedTestCase(unittest.TestCase):
   'X509 Store tests'

   serial = 7
   revokedOn = POW.pkix.time2utc(1005960447)

   def testRevoked(self):
      'Create X509 revocation and check values are correct'
      rev = POW.X509Revoked( self.serial, self.revokedOn )
      self.failUnlessEqual( rev.getDate(), self.revokedOn )
      self.failUnlessEqual( rev.getSerial(), self.serial )

#--------------- X509 Revoked test case ---------------#
#--------------- X509 CRL test case ---------------#

class X509CrlTestCase(unittest.TestCase):
   'X509 CRL tests'

   revocationData = (   ( 1, POW.pkix.time2utc(1005960447) ),
                        ( 2, POW.pkix.time2utc(1005960448) ),
                        ( 3, POW.pkix.time2utc(1005960449) ),
                        ( 4, POW.pkix.time2utc(1005960450) ),
                        ( 5, POW.pkix.time2utc(1005960451) )    )

   thisUpdate = POW.pkix.time2utc(1005960447)
   nextUpdate = POW.pkix.time2utc(1037496447)

   version = 2

   def setUp(self):
      self.ca = certs.getCert('ca')
      self.caCipher = ciphers.getCipher('ca')

      revocations = []
      for rev in self.revocationData:
         revocation = POW.X509Revoked( rev[0], rev[1] )
         revocations.append( revocation )

      self.crl = POW.X509Crl()
      self.crl.setVersion( self.version )
      self.crl.setIssuer( self.ca.getIssuer() )
      self.crl.setThisUpdate( self.thisUpdate )
      self.crl.setNextUpdate( self.nextUpdate )
      self.crl.setRevoked( revocations )
      self.crl.sign( self.caCipher[1] )

   def tearDown(self):
      del self.ca
      del self.caCipher
      del self.crl

   def testPemIo(self):
      'Read and write CRL in PEM format'
      pemCrl = self.crl.pemWrite()
      newCrl = POW.pemRead( POW.X509_CRL, pemCrl )
      self.failUnlessEqual( self.version, newCrl.getVersion() )

   def testDerIo(self):
      'Read and write CRL in DER format'
      derCrl = self.crl.derWrite()
      newCrl = POW.derRead( POW.X509_CRL, derCrl )
      self.failUnlessEqual( self.version, newCrl.getVersion() )

   def testVersion(self):
      'Create CRL and check version number is correct'
      self.failUnlessEqual( self.version, self.crl.getVersion() )

   def testIssuer(self):
      'Create CRL and check issuer name is correct'
      self.failUnlessEqual( self.ca.getIssuer(), self.crl.getIssuer() )

   def testThisUpdate(self):
      'Create CRL and check thisUpdate is correct'
      self.failUnlessEqual( self.thisUpdate, self.crl.getThisUpdate() )

   def testNextUpdate(self):
      'Create CRL and check nextUpdate is correct'
      self.failUnlessEqual( self.nextUpdate, self.crl.getNextUpdate() )

   def testRevoked(self):
      'Create CRL and check list of revoked objects is correct'
      revokedCerts = self.crl.getRevoked()
      for i in range( len(revokedCerts) ):
         revocation = revokedCerts[i]
         serial = revocation.getSerial()
         date = revocation.getDate()
         index = serial - 1
         self.failUnlessEqual( self.revocationData[index][0], serial )
         self.failUnlessEqual( self.revocationData[index][1], date )



   def crlIssuerAltNameTest(self):
      'CRL Issuer Alt Name tests'

      n1 = ('directoryName',  (  (( o2i('countryName'), ('printableString', 'UK') ),), 
                                 (( o2i('stateOrProvinceName'), ('printableString', 'Herts') ),), 
                                 (( o2i('organizationName'), ('printableString', 'The House') ),),
                                 (( o2i('commonName'), ('printableString', 'Shannon Works') ),) ) ) 

      n2 = ('rfc822Name', 'peter_shannon@yahoo.com')
      n3 = ('uri', 'http://www.p-s.org.uk') 
      n4 = ('iPAddress', POW.pkix.ip42oct(192,168,100,51)) 

      issuer = POW.pkix.IssuerAltName()
      issuer.set([n1,n2,n3,n4]) 
      self.crl.addExtension( 'issuerAltName', 0, issuer.toString() )
      issuer = POW.pkix.IssuerAltName()
      issuer.fromString( self.crl.getExtension(0)[2] )
      values = issuer.get()
      self.failUnless( values == (n1,n2,n3,n4), 'generalNames are incorrect')

   def crlExtensionManipulationTest(self):
      'Extension manipulation for CRL object tests'

      n1 = ('directoryName',  (  (( o2i('countryName'), ('printableString', 'UK') ),), 
                                 (( o2i('stateOrProvinceName'), ('printableString', 'Herts') ),), 
                                 (( o2i('organizationName'), ('printableString', 'The House') ),),
                                 (( o2i('commonName'), ('printableString', 'Shannon Works') ),) ) ) 

      n2 = ('rfc822Name', 'peter_shannon@yahoo.com')
      n3 = ('uri', 'http://www.p-s.org.uk') 
      n4 = ('iPAddress', POW.pkix.ip42oct(192,168,100,51)) 

      issuer = POW.pkix.IssuerAltName()
      issuer.set((n1,n2,n3,n4)) 
      self.crl.addExtension( 'issuerAltName', 0, issuer.toString() )
      self.crl.addExtension( 'issuerAltName', 0, issuer.toString() )
      self.failUnless( self.crl.countExtensions() == 2, 'CRL should have 2 any extensions')
      self.crl.clearExtensions()
      self.failUnless( self.crl.countExtensions() == 0, 'CRL should have no extensions')
      self.crl.addExtension( 'issuerAltName', 0, issuer.toString() )

      issuer = POW.pkix.IssuerAltName()
      issuer.fromString( self.crl.getExtension(0)[2] )
      self.failUnless( issuer.get() == (n1,n2,n3,n4), 'incorrect extension handling ')


      issuer = POW.pkix.IssuerAltName()
      issuer.fromString( self.crl.getExtension(0)[2] )
      values = issuer.get()
      self.failUnless( values == (n1,n2,n3,n4), 'generalNames are incorrect')

   def revExtensionManipulationTest(self):
      'Extension manipulation for CRL revocation object tests'
      invalid = POW.pkix.InvalidityDate()
      invalid.set( POW.pkix.time2gen(time.time()) ) 
      reason = POW.pkix.CrlReason()
      reason.set(1)

      revdata = self.revocationData[0]
      revo = POW.X509Revoked( revdata[0], revdata[1] )
      revo.addExtension( 'invalidityDate', 0, invalid.toString() )
      revo.addExtension( 'CRLReason', 0, reason.toString() )
      self.failUnless( revo.countExtensions() == 2, 'revocation should have 2 any extensions')
      revo.clearExtensions()
      self.failUnless( revo.countExtensions() == 0, 'revocation should have no extensions')
      revo.addExtension( 'CRLReason', 0, reason.toString() )
      revo.addExtension( 'invalidityDate', 0, invalid.toString() )
      reason = POW.pkix.CrlReason()
      reason.fromString( revo.getExtension(0)[2] )
      self.failUnless( reason.get() == 1, 'incorrect extension handling ')

   def revocationExtensionTest(self):
      'CRL Revocation Extension tests'
      self.ca = certs.getCert('ca')
      self.caCipher = ciphers.getCipher('ca')

      revocations = []
      invalid = POW.pkix.InvalidityDate()
      invalid.set( POW.pkix.time2gen(time.time()) ) 
      reason = POW.pkix.CrlReason()
      reason.set(1)
      for rev in self.revocationData:
         revocation = POW.X509Revoked( rev[0], rev[1] )
         revocation.addExtension( 'invalidityDate', 0, invalid.toString() )
         revocation.addExtension( 'CRLReason', 0, reason.toString() )
         revocations.append( revocation )

      self.crl = POW.X509Crl()
      self.crl.setVersion( self.version )
      self.crl.setIssuer( self.ca.getIssuer() )
      self.crl.setThisUpdate( self.thisUpdate )
      self.crl.setNextUpdate( self.nextUpdate )
      self.crl.setRevoked( revocations )
      self.crl.sign( self.caCipher[1] )



#--------------- X509 CRL test case ---------------#
#--------------- SSL test case ---------------#

serverPort = 7777
clientMsg = 'Message from client to server...'
serverMsg = 'Message from server to client...'

def serverCertKey():
   cert = certs.getCert('server')
   key = ciphers.getCipher('server')[1]
   return cert, key

def clientCertKey():
   cert = certs.getCert('client')
   key = ciphers.getCipher('client')[1]
   return cert, key

class SimpleSslServer:

   def __init__(self, test):
      cert, key = serverCertKey()
      ssl = POW.Ssl( POW.SSLV23_SERVER_METHOD )
      ssl.useCertificate(cert)
      ssl.useKey(key)

      sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
      sock.bind( ('', serverPort) )
      sock.listen(1)
      conn, addr = sock.accept()
      sock.shutdown(0)
      sock.close()
      ssl.setFd( conn.fileno() )
      ssl.accept()

      msg = ssl.read()
      ssl.write(serverMsg)
      
      while 1:
         try: ssl.shutdown(); break
         except: time.sleep(1)

      conn.shutdown(0)
      conn.close()     
      test.failUnlessEqual( clientMsg, msg, 'client/server communication failiure' )

class ValidatingSslServer:

   def __init__(self, test):
      cert, key = serverCertKey()
      ssl = POW.Ssl( POW.SSLV23_SERVER_METHOD )
      ssl.useCertificate(cert)
      ssl.useKey(key)
      ssl.setVerifyMode( POW.SSL_VERIFY_PEER )

      store = POW.X509Store()
      store.addTrust( certs.getCert('ca') )

      sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
      sock.bind( ('', serverPort) )
      sock.listen(1)
      conn, addr = sock.accept()
      sock.shutdown(0)
      sock.close()
      ssl.setFd( conn.fileno() )
      ssl.accept()

      clientCert = ssl.peerCertificate()

      msg = ssl.read()
      ssl.write(serverMsg)
      
      while 1:
         try: ssl.shutdown(); break
         except: time.sleep(1)

      conn.shutdown(0)
      conn.close()     
      test.failUnless( store.verify( clientCert ), 'client certificate failed verification' )

class SslClient:

   def __init__(self, test):
      cert, key = clientCertKey()
      ssl = POW.Ssl( POW.SSLV23_CLIENT_METHOD )
      ssl.useCertificate(cert)
      ssl.useKey(key)
      sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
      sock.connect( ('', serverPort) )
      ssl.setFd( sock.fileno() )
      ssl.connect()

      ssl.write(clientMsg)
      ssl.read()
      
      while 1:
         try: ssl.shutdown(); break
         except: time.sleep(1)

      sock.shutdown(0)
      sock.close()     

class ValidatingSslClient:

   def __init__(self, test):
      cert, key = clientCertKey()
      ssl = POW.Ssl( POW.SSLV23_CLIENT_METHOD )
      ssl.useCertificate(cert)
      ssl.useKey(key)
      ssl.setVerifyMode( POW.SSL_VERIFY_PEER )

      store = POW.X509Store()
      store.addTrust( certs.getCert('ca') )

      sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
      sock.connect( ('', serverPort) )
      ssl.setFd( sock.fileno() )
      ssl.connect()

      serverCert = ssl.peerCertificate()

      ssl.write(clientMsg)
      ssl.read()
      
      while 1:
         try: ssl.shutdown(); break
         except: time.sleep(1)

      sock.shutdown(0)
      sock.close()     
      test.failUnless( store.verify( serverCert ), 'client certificate failed verification' )



class SslTestCase(unittest.TestCase):
   'SSL tests'

   def testSimple(self):
      '''Test client/server communication over SSL'''
      global serverPort
      serverPort += 1
      pid = os.fork()
      if pid:
         time.sleep(1)
         SimpleSslServer(self)
      else:
         time.sleep(3)
         SslClient(self)
         os._exit(0)

   def testClientValidation(self):
      '''Request and validate client certificate'''
      global serverPort
      serverPort += 1
      pid = os.fork()
      if pid:
         time.sleep(1)
         ValidatingSslServer(self)
      else:
         time.sleep(3)
         SslClient(self)
         os._exit(0)

   def testServerValidation(self):
      '''Request and validate server certificate'''
      global serverPort
      serverPort += 1
      pid = os.fork()
      if pid:
         time.sleep(3)
         ValidatingSslClient(self)
      else:
         time.sleep(1)
         SimpleSslServer(self)
         os._exit(0)

#--------------- SSL test case ---------------#
#--------------- Test suite generators ---------------#

def derEncodingTests():
   suite = unittest.TestSuite()
   suite.addTest( DerEncodingTestCase('integerTest') )
   suite.addTest( DerEncodingTestCase('oidTest') )
   suite.addTest( DerEncodingTestCase('booleanTest') )
   suite.addTest( DerEncodingTestCase('bitStringTest') )
   return suite

def complexDerTests():
   suite = unittest.TestSuite()
   suite.addTest( ComplexDerTestCase('emptySeqTest') )
   suite.addTest( ComplexDerTestCase('seqOfSimpleTest') )
   suite.addTest( ComplexDerTestCase('seqOfSeqTest') )
   suite.addTest( ComplexDerTestCase('seqOfSimpleWithOptionalTest') )
   suite.addTest( ComplexDerTestCase('seqOfSimpleWithDefaultTest') )
   suite.addTest( ComplexDerTestCase('seqOfOptionalSeqTest') )
   suite.addTest( ComplexDerTestCase('seqOfPartiallySetOptionalSeqTest') )
   suite.addTest( ComplexDerTestCase('defaultSeqTest') )
   suite.addTest( ComplexDerTestCase('sequenceOfChoiceTest') )
   suite.addTest( ComplexDerTestCase('seqOfDefaultSeqTest') )
   suite.addTest( ComplexDerTestCase('sequenceOfSimpleTest') )
   suite.addTest( ComplexDerTestCase('defaultSequenceOfTest') )
   suite.addTest( ComplexDerTestCase('sequenceOfDefaultSequenceOfTest') )
   suite.addTest( ComplexDerTestCase('optionalSequenceOfTest') )
   suite.addTest( ComplexDerTestCase('sequenceOfOptionalSequenceOfTest') )
   suite.addTest( ComplexDerTestCase('basicExplicitTest') )
   suite.addTest( ComplexDerTestCase('defaultExplicitTest') )
   suite.addTest( ComplexDerTestCase('optionalExplicitTest') )
   suite.addTest( ComplexDerTestCase('basicChoiceTest') )
   suite.addTest( ComplexDerTestCase('defaultChoiceTest') )
   suite.addTest( ComplexDerTestCase('optionalChoiceTest') )
   suite.addTest( ComplexDerTestCase('choiceWithDefaultElementTest') )
   return suite

def pkixTests():
   suite = unittest.TestSuite()
   suite.addTest( PkixTestCase('validityTest') )
   suite.addTest( PkixTestCase('directoryStringTest') )
   suite.addTest( PkixTestCase('attributeTypeAndValueTest') )
   suite.addTest( PkixTestCase('x509v2Test') )
   suite.addTest( PkixTestCase('basicConstraintsTest') )
   suite.addTest( PkixTestCase('generalNameTest') )
   suite.addTest( PkixTestCase('x509v3Test') )
   suite.addTest( PkixTestCase('crlv1Test') )
   return suite

def x509ExtensionSuite():
   suite = unittest.TestSuite()
   suite.addTest( ExtensionsTestCase('extensionManipulationTest') )
   suite.addTest( ExtensionsTestCase('basicConstraintTest') )
   suite.addTest( ExtensionsTestCase('privateKeyUsagePeriodTest') )
   suite.addTest( ExtensionsTestCase('keyUsageTest') )
   suite.addTest( ExtensionsTestCase('issuerAltNameTest') )
   suite.addTest( ExtensionsTestCase('subjectAltNameTest') )
   suite.addTest( ExtensionsTestCase('certPolicyTest') )
   return suite

def hashSuite():
   suite = unittest.TestSuite()
   suite.addTest( HashTestCase('testMd2') )
   suite.addTest( HashTestCase('testMd5') )
   suite.addTest( HashTestCase('testSha') )
   suite.addTest( HashTestCase('testSha1') )
   suite.addTest( HashTestCase('testRipemd160') )
   return suite

def hmacSuite():
   suite = unittest.TestSuite()
   suite.addTest( HmacTestCase('testHmacMd2') )
   suite.addTest( HmacTestCase('testHmacMd5') )
   suite.addTest( HmacTestCase('testHmacSha') )
   suite.addTest( HmacTestCase('testHmacSha1') )
   suite.addTest( HmacTestCase('testHmacRipemd160') )
   return suite

def symmetricSuite():
   suite = unittest.TestSuite()
   if 'DES_ECB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_ECB') )
   if 'DES_EDE' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_EDE') )
   if 'DES_EDE3' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_EDE3') )
   if 'DES_CFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_CFB') )
   if 'DES_EDE_CFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_EDE_CFB') )
   if 'DES_EDE3_CFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_EDE3_CFB') )
   if 'DES_OFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_OFB') )
   if 'DES_EDE_OFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_EDE_OFB') )
   if 'DES_EDE3_OFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_EDE3_OFB') )
   if 'DES_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_CBC') )
   if 'DES_EDE_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_EDE_CBC') )
   if 'DES_EDE3_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDES_EDE3_CBC') )
   if 'DESX_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testDESX_CBC') )
   if 'RC4' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC4') )
   if 'RC4_40' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC4_40') )
   if 'IDEA_ECB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testIDEA_ECB') )
   if 'IDEA_CFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testIDEA_CFB') )
   if 'IDEA_OFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testIDEA_OFB') )
   if 'IDEA_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testIDEA_CBC') )
   if 'RC2_ECB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC2_ECB') )
   if 'RC2_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC2_CBC') )
   if 'RC2_40_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC2_40_CBC') )
   if 'RC2_CFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC2_CFB') )
   if 'RC2_OFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC2_OFB') )
   if 'BF_ECB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testBF_ECB') )
   if 'BF_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testBF_CBC') )
   if 'BF_CFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testBF_CFB') )
   if 'BF_OFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testBF_OFB') )
   if 'CAST5_ECB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testCAST5_ECB') )
   if 'CAST5_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testCAST5_CBC') )
   if 'CAST5_CFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testCAST5_CFB') )
   if 'CAST5_OFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testCAST5_OFB') )
   if 'RC5_32_12_16_CBC' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC5_32_12_16_CBC') )
   if 'RC5_32_12_16_CFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC5_32_12_16_CFB') )
   if 'RC6_32_12_16_ECB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC5_32_12_16_ECB') )
   if 'RC5_32_12_16_OFB' in POW.__dict__.keys():
      suite.addTest( SymmetricTestCase('testRC5_32_12_16_OFB') )
   return suite

def asymmetricSuite():
   suite = unittest.TestSuite()
   suite.addTest( AsymmetricTestCase('testPemIo') )
   suite.addTest( AsymmetricTestCase('testDerIo') )
   suite.addTest( AsymmetricTestCase('testPublicEncrypt') )
   suite.addTest( AsymmetricTestCase('testPrivateEncrypt') )
   suite.addTest( AsymmetricTestCase('testSign') )
   return suite

def x509Suite():
   suite = unittest.TestSuite()
   suite.addTest( X509TestCase('testPemIo') )
   suite.addTest( X509TestCase('testDerIo') )
   suite.addTest( X509TestCase('testIssuer') )
   suite.addTest( X509TestCase('testSubject') )
   suite.addTest( X509TestCase('testVersion') )
   suite.addTest( X509TestCase('testSerial') )
   suite.addTest( X509TestCase('testNotBefore') )
   suite.addTest( X509TestCase('testNotAfter') )
   return suite

def x509StoreSuite():
   suite = unittest.TestSuite()
   suite.addTest( X509StoreTestCase('testVerify') )
   suite.addTest( X509StoreTestCase('testVerifyChain') )
   return suite

def x509RevokedSuite():
   suite = unittest.TestSuite()
   suite.addTest( X509RevokedTestCase('testRevoked') )
   return suite

def x509CrlSuite():
   suite = unittest.TestSuite()
   suite.addTest( X509CrlTestCase('testPemIo') )
   suite.addTest( X509CrlTestCase('testDerIo') )
   suite.addTest( X509CrlTestCase('testVersion') )
   suite.addTest( X509CrlTestCase('testIssuer') )
   suite.addTest( X509CrlTestCase('testThisUpdate') )
   suite.addTest( X509CrlTestCase('testNextUpdate') )
   suite.addTest( X509CrlTestCase('testRevoked') )
   suite.addTest( X509CrlTestCase('crlIssuerAltNameTest') )
   suite.addTest( X509CrlTestCase('revExtensionManipulationTest') )
   suite.addTest( X509CrlTestCase('revocationExtensionTest') )
   suite.addTest( X509CrlTestCase('crlExtensionManipulationTest') )
   return suite

def sslSuite():
   suite = unittest.TestSuite()
   suite.addTest( SslTestCase('testSimple') )
   suite.addTest( SslTestCase('testClientValidation') )
   suite.addTest( SslTestCase('testServerValidation') )
   return suite

#--------------- Test suite generators ---------------#
#--------------- main ---------------#

if __name__ == '__main__':
   print '\n\tGenerating RSA keys and certificates to use for testing...\n'

   certs = X509Utilities()
   ciphers = certs.asymUtils
   certs.prepCerts()

   runner = unittest.TextTestRunner( sys.stderr, 1, 2)
   runner.run( derEncodingTests() )
   runner.run( complexDerTests() )
   runner.run( pkixTests() )
   runner.run( hashSuite() )
   runner.run( hmacSuite() )
   runner.run( symmetricSuite() )
   runner.run( asymmetricSuite() )
   runner.run( x509Suite() )
   runner.run( x509StoreSuite() )
   runner.run( x509RevokedSuite() )
   runner.run( x509CrlSuite() )
   runner.run( x509ExtensionSuite() )
   if sys.platform != 'win32':
      runner.run( sslSuite() )

   certs.unPrepCerts()

#--------------- main ---------------#
