# $Id$

"""
Command line program to simulate behavior of the IR back-end.
"""

import glob, rpki.left_right, xml.sax, lxml.etree, lxml.sax, POW, POW.pkix, getopt, sys

rng = lxml.etree.RelaxNG(lxml.etree.parse("left-right-schema.rng"))

class command(object):
  options = ()

  def getopt(self, argv):
    if options:
      opts, args = getopt.getopt(argv, "", [x[2:] for x in self.options])
      for o, a in opts:
        getattr(self, o[2:])(a)
      return args
    else:
      return argv

  def self_id(self, arg):
    self.self_id = arg



class help(command):
  def run(self, msg):
    print "Usage:", sys.argv[0]
    for k,v in dispatch.iteritems():
      print " ".join((k,) + v.options)

class self(command):
  options = ("--action", "--self_id", "--extension")

  def __init__(self):
    self.extensions = {}

  def extension(self, arg):
    kv = arg.split(":", 1)
    self.extensions[k] = v

  def run(self, msg):
    pdu = rpki.left_right.self_elt()
    


dispatch = dict((x.__name__, x) for x in (help, self))

msg = rpki.left_right.msg()

argv = sys.argv[1:]
while argv:
  cmd = dispatch[argv[0]]
  argv = getopt(argv[1:])
  cmd.run(msg)

