# $Id$

"""
Command line program to simulate behavior of the IR back-end.
"""

import glob, rpki.left_right, rpki.relaxng, getopt, sys, lxml.etree

class command(object):

  def getopt(self, argv):
    if self.options:
      opts, args = getopt.getopt(argv, "", [x[2:] + "=" for x in self.options])
      for o, a in opts:
        getattr(self, o[2:])(a)
      return args
    else:
      return argv

  def process(self, msg):
    msg.append(self.pdu)

  def action(self, arg):
    self.pdu.action = arg
    self.pdu.type = "query"

  def self_id(self, arg):
    self.pdu.self_id = arg

class help(command):
  options = ()

  def process(self, msg):
    print "Usage:", sys.argv[0]
    for k,v in dispatch.iteritems():
      print " ", " ".join((k,) + v.options)

class self(command):
  options = ("--action", "--self_id", "--extension")

  def __init__(self):
    self.pdu = rpki.left_right.self_elt()

  def extension(self, arg):
    kv = arg.split(":", 1)
    self.pdu.extensions[k] = v
    
dispatch = dict((x.__name__, x) for x in (help, self))

rng = rpki.relaxng.RelaxNG("left-right-schema.rng")

msg = rpki.left_right.msg()

argv = sys.argv[1:]
while argv:
  cmd = dispatch[argv[0]]()
  argv = cmd.getopt(argv[1:])
  cmd.process(msg)

if msg:
  elt = msg.toXML()
  rng.assertValid(elt)
  print lxml.etree.tostring(elt, pretty_print=True, encoding="us-ascii", xml_declaration=True)
