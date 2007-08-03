# $Id$

"""
Command line program to simulate behavior of the IR back-end.
"""

import glob, rpki.left_right, xml.sax, lxml.etree, lxml.sax, POW, POW.pkix, getopt, sys

rng = lxml.etree.RelaxNG(lxml.etree.parse("left-right-schema.rng"))

class command(object):
  options = ()

  def __init__(self, argv):
    opts, args = getopt.getopt(argv[2:], "", [x[2:] for x in self.options])
    for o, a in opts:
      getattr(self, o[2:])(a)

class help(command):
  options = ('--tweedledee', '--tweedledum')

  def tweedledee(self, arg): print "tweedledee"

  def tweedledum(self, arg): print "tweedledum"

  def __call__(self):
    print "Boy this sure is an interesting help command, huh?"

class wombat(command):
  def __call__(self):
    print "I am the wombat!"

top_dispatch = dict((x.__name__, x) for x in (help, wombat))

cmd = top_dispatch[sys.argv[1]](sys.argv)
cmd()

if False:

  dispatch = { "--help"   : help, "--usage"  : usage, "--wombat" : wombat }
  try:
    opts, args = getopt.getopt(sys.argv[1:], "", [x[2:] for x in dispatch.keys()])
  except getopt.GetoptError:
    print "You're confused, aren't you?"
    sys.exit(1)
  for o, a in opts:
    dispatch[o]()
