#!/usr/bin/env python

import sys, string, os, commands
 
class DocError(Exception):
   def __init__(self, mesg):
      self.mesg = mesg

   def __str__(self):
      return self.mesg

class Extractor:
   def __init__(self, module):
      exec('import %s' % module)
      self.module = eval(module)

   def get(self):
      fragments = ''
      for doc in self.module._docset():
         fragments += doc

      return '<moduleSet>' + fragments + '</moduleSet>' 


if __name__ == '__main__':
   if len(sys.argv) < 2:
      raise DocError( 'module name must be supplied')

   lines = ''
   for mod in sys.argv[1:]:
      print 'processing module', mod
      ex = Extractor(mod)
      lines += ex.get()

   file = open('fragments.xml', 'w')
   file.write('%s\n%s\n%s' % ('<collection>', lines, '</collection>'))
   file.close()

   print 'transforming document...'
   (status, doc) = commands.getstatusoutput('java org.apache.xalan.xslt.Process -IN fragments.xml -XSL doc.xsl' )
   if status:
      print doc
      sys.exit(1)

   doc = doc.replace('/>', '>')
   lines = string.split(doc, '\n')
   lines[0] = '<!DOCTYPE book PUBLIC "-//OASIS//DTD DocBook V4.1//EN">'

   file = open(sys.argv[1] + '.sgm', 'w')
   file.write( string.join(lines, '\n') )
   file.close()

