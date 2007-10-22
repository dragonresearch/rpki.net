# $Id$

"""Script to generate rpki/relaxng.py."""

print "# Automatically generated, do not edit."
print
print "import lxml.etree"

for varname, filename in (("left_right", "left-right-schema.rng"),
                          ("up_down",    "up-down-schema.rng")):
  f = open(filename)
  print "\n## @var %s\n## Parsed RelaxNG %s schema\n%s = lxml.etree.RelaxNG(lxml.etree.fromstring('''%s'''))" % (varname, varname, varname, f.read())
  f.close()
