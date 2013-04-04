import sys
import getopt
import textwrap

from lxml.etree import Element, SubElement, ElementTree

text_wrapper = textwrap.TextWrapper()
item_wrapper = textwrap.TextWrapper(initial_indent = "  ", subsequent_indent = "  ")
conf_wrapper = textwrap.TextWrapper(initial_indent = "# ", subsequent_indent = "# ")

class Option(object):

  def __init__(self, name, value, doc):
    self.name = name
    self.value = value
    self.doc = doc

  @property
  def width(self):
    return len(self.name)

  def to_xml(self):
    x = Element("option", name = self.name, value = self.value)
    for d in self.doc:
      SubElement(x, "doc").text = "\n" + text_wrapper.fill(d) + "\n"
    return x

  def to_wiki(self, f):
    f.write("\n%s::" % self.name)
    for d in self.doc:
      f.write("\n%s\n" % item_wrapper.fill(d))

  def to_conf(self, f, width):
    for d in self.doc:
      f.write("\n%s\n" % conf_wrapper.fill(d))
    f.write("\n%-*s = %s\n" % (width, self.name, self.value))

class Section(object):

  def __init__(self, name):
    self.name = name
    self.doc = []
    self.options = []

  @property
  def width(self):
    return max(o.width for o in self.options)

  @classmethod
  def from_xml(cls, elt):
    self = cls(name = elt.get("name"))
    for x in elt.iterchildren("doc"):
      self.doc.append(" ".join(x.text.split()))
    for x in elt.iterchildren("option"):
      self.options.append(Option(name = x.get("name"), value = x.get("value"),
                                 doc = [" ".join(d.text.split())
                                        for d in x.iterchildren("doc")]))
    return self

  def to_xml(self):
    x = Element("section", name = self.name)
    for d in self.doc:
      SubElement(x, "doc").text = "\n" + text_wrapper.fill(d) + "\n"
    x.extend(o.to_xml() for o in self.options)
    return x

  def to_wiki(self, f):
    f.write('''\
{{{
#!comment
THIS PAGE WAS GENERATED AUTOMATICALLY, DO NOT EDIT.

Generated from ''' + ident + '''
by $Id$
}}}

= ![''' + self.name + '''] section =
''')
    for d in self.doc:
      f.write("\n%s\n" % text_wrapper.fill(d))
    for o in self.options:
      o.to_wiki(f)

  def to_conf(self, f, width):
    f.write('''
################################################################################

[''' + self.name + ''']
''')
    for d in self.doc:
      f.write("\n%s\n" % conf_wrapper.fill(d))
    for o in self.options:
      o.to_conf(f, width)

sections = []
index = None
ident = None

opts, argv = getopt.getopt(sys.argv[1:], "", ["read-xml=", "write-xml=", "write-wiki=", "write-conf=", "set="])
for o, a in opts:

  if o == "--read-xml":
    index = None
    root = ElementTree(file = a).getroot()
    ident = root.get("ident")
    sections.extend(Section.from_xml(x) for x in root)
    index = {}
    for section in sections:
      for option in section.options:
        name = (section.name, option.name)
        if name in index:
          sys.exit("Duplicate entry for section \"%s\" option \"%s\"" % name)
        index[name] = option

  elif o == "--set":
    try:
      name, value = a.split("=", 1)
      section, option = name.split(":")
    except ValueError:
      sys.exit("Couldn't parse --set specification \"%s\"" % a)
    name = (section, option)
    if name not in index:
      sys.exit("Couldn't find section \"%s\" option \"%s\"" % name)
    index[name].value = value

  elif o == "--write-xml":
    x = Element("configuration", ident = ident)
    x.extend(s.to_xml() for s in sections)
    ElementTree(x).write(a, pretty_print = True, encoding = "us-ascii")

  elif o == "--write-wiki":
    with open(a, "w") as f:
      for i, section in enumerate(sections):
        if i:
          f.write("\f\n")
        section.to_wiki(f)

  elif o == "--write-conf":
    with open(a, "w") as f:
      f.write('''\
# Automatically generated.  Edit if you like, but be careful of overwriting.
# Generated from ''' + ident + '''
# by $Id
''')
      width = max(s.width for s in sections)
      for section in sections:
        section.to_conf(f, width)

if argv:
  sys.exit("Unexpected arguments %s" % argv)
