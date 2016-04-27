#!/usr/bin/env python

# $Id$

"""
Unpickle CA state packaged by ca-pickle.

This version is a stub, and exists only to test ca-pickle.
"""

import sys
import cPickle
import argparse
import subprocess

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("input", help = "input file")
args = parser.parse_args()

xzcat = subprocess.Popen(("xzcat", args.input), stdout = subprocess.PIPE)
world = cPickle.load(xzcat.stdout)
if xzcat.wait() != 0:
    sys.exit("XZ unpickling failed with code {}".format(xz.returncode))

print "import datetime"
print "world =", repr(world)
