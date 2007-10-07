# $Id$

print "# Automatically generated, do not edit."
print
print "import lxml.etree"

for varname, filename in (("left_right", "left-right-schema.rng"),
                          ("up_down",    "up-down-schema.rng")):
  print "## @var %s" % varname
  print "## Parsed RelaxNG %s schema" % varname
  f = open(filename)
  print "\n%s = lxml.etree.RelaxNG(lxml.etree.fromstring('''%s'''))" % (varname, f.read())
  f.close()
