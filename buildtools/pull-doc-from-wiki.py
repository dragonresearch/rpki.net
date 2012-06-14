"""
Pull HTML pages from a Trac Wiki, feed the useful bits to htmldoc and
html2text to generate PDF and flat text documentation.

Assumes you're using the TracNav plugin for the Wiki pages, and uses
the same list as the TracNav plugin does to determine the set of pages
to convert and the order in which they appear in the PDF file.

Most of the work of massaging the HTML is done using XSL transforms,
because the template-driven style makes that easy.  There's probably
some clever way to use lxml's XPath code to do the same thing in a
more pythonic way with ElementTrees, but I already had the XSL
transforms and there's a point of diminishing returns on this sort of
thing.

$Id$

Copyright (C) 2012  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import sys
import os
import getopt
import lxml.etree
import urllib
import urlparse
import subprocess
import tempfile

# Main program, up front so it doesn't get lost under all the XSL

def main():

  base  = "https://trac.rpki.net"
  toc   = base + "/wiki/doc/RPKI/TOC"
  pdf   = "manual.pdf"
  dir   = "."
  h2trc = os.path.join(os.path.dirname(sys.argv[0]), "html2textrc")

  options = ["base_url=", "directory=", "help", "html2textrc", "pdf_file=", "toc="]

  def usage(msg = 0):
    sys.stderr.write("Usage: %s %s\n" % (
      sys.argv[0], " ".join("[--%s value]" % o[:-1] if o.endswith("=") else "[--%s]" % o
                            for o in options)))
    sys.stderr.write(__doc__)
    sys.exit(msg)

  opts, argv = getopt.getopt(sys.argv[1:], "b:d:hp:r:t:?", options)
  for o, a in opts:
    if o in ("-h", "--help", "-?"):
      usage()
    elif o in ("-b", "--base_url"):
      base = a
    elif o in ("-d", "--directory"):
      dir = a
    elif o in ("-p", "--pdf_file"):
      pdf = a
    elif o in ("-r", "--html2textrc"):
      h2trc = a
    elif o in ("-t", "--toc"):
      toc = a
  if argv:
    usage("Unexpected arguments %s" % argv)

  urls = str(xsl_get_toc(lxml.etree.parse(urllib.urlopen(toc)).getroot(),
                         basename = repr(base))).splitlines()

  assert all(urlparse.urlparse(url).path.startswith("/wiki/") for url in urls)

  htmldoc = subprocess.Popen(
    ("htmldoc", "--book", "--title", "--outfile", pdf, "--format", "pdf",
     "--firstpage", "p1", "--size", "Universal", "--no-duplex",
     "--fontsize", "11.0", "--fontspacing", "1.1", "--headfootsize", "11.0",
     "--headingfont", "Helvetica", "--bodyfont", "Times", "--headfootfont", "Helvetica-Oblique",
     "-"), stdin = subprocess.PIPE)

  lxml.etree.ElementTree(xml_title).write(htmldoc.stdin)

  png_fns = []

  for url in urls:
    path = urlparse.urlparse(url).path
    page = xsl_get_page(lxml.etree.parse(urllib.urlopen(url)).getroot(),
                        basename = repr(base),
                        path = repr(path))

    for img in page.xpath("//img | //object | //embed"): 
      attr = "data" if img.tag == "object" else "src"
      img_url = img.get(attr)
      if img_url.endswith(".svg"):
        #sys.stderr.write("Converting %s to PNG\n" % img_url)
        png_fd, png_fn = tempfile.mkstemp(suffix = ".png")
        subprocess.Popen(("svg2png", "-h", "700", "-w", "600", "-", "-"),
                         stdout = png_fd,
                         stdin = subprocess.PIPE).communicate(urllib.urlopen(img_url).read())
        os.close(png_fd)
        img.set(attr, png_fn)
        png_fns.append(png_fn)

    page.write(htmldoc.stdin)

    html2text = subprocess.Popen(("html2text", "-rcfile", h2trc, "-nobs", "-ascii"),
                                 stdin = subprocess.PIPE,
                                 stdout = subprocess.PIPE)
    page.write(html2text.stdin)
    html2text.stdin.close()
    lines = html2text.stdout.readlines()
    html2text.stdout.close()
    html2text.wait()

    while lines and lines[0].isspace():
      del lines[0]

    fn = os.path.join(dir, path[len("/wiki/"):].replace("/", "."))
    f = open(fn, "w")
    want_blank = False
    for line in lines:
      blank = line.isspace()
      if want_blank and not blank:
        f.write("\n")
      if not blank:
        f.write(line)
      want_blank = blank
    f.close()
    sys.stderr.write("Wrote %s\n" % fn)

  htmldoc.stdin.close()
  htmldoc.wait()
  sys.stderr.write("Wrote %s\n" % pdf)

  for png_fn in png_fns:
    os.unlink(png_fn)

# HTMLDOC title page.  At some point we might want to generate this
# dynamically as an ElementTree, but static content will do for the
# moment.

xml_title = lxml.etree.HTML('''\
  <html>
    <head>
      <meta name="author" content="http://rpki.net">
      <title>RPKI Tools Manual</title>
    </head>
    <body>
    </body>
  </html>
''')

# XSL transform to extract list of Wiki page URLs from the TOC Wiki page

xsl_get_toc = lxml.etree.XSLT(lxml.etree.XML('''\
  <xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                 version="1.0">

    <xsl:output method="text" encoding="us-ascii"/>

    <xsl:param name="basename"/>

    <xsl:template match="/">
      <xsl:for-each select="//div[@id = 'wikipage']/ul//a">
        <xsl:value-of select="concat($basename, @href, '&#10;')"/>
      </xsl:for-each>
    </xsl:template>

  </xsl:transform>
'''))

# XSL transform to extract useful content of a Wiki page.

# Django generates weird HTML for ordered lists: it sometimes breaks
# up a single ordered list into multiple adjacent <ol/> elements,
# using the @start attribute to try to make the result look like a
# single ordered list.  This looks OK in Firefox but confuses the
# bejesus out of both html2text and htmldoc.  In some cases this is
# probably unavoidable, but most of the uses of this I've seen look
# gratuitous, and are probably the result of code modulararity issues
# in Django.
#
# So we try to clean this up, by merging adjacent <ol/> elements where
# we can.  The merge incantation is an adaptation of:
#
# http://stackoverflow.com/questions/1806123/merging-adjacent-nodes-of-same-type-xslt-1-0
#
# There may be a more efficient way to do this, but I don't think
# we care, and this seems to work.
#
# Original author's explanation:
# 
# The rather convoluted XPath expression for selecting the following
# sibling aaa nodes which are merged with the current one:
#
# following-sibling::aaa[                       # following 'aaa' siblings
#   not(preceding-sibling::*[                   #   if they are not preceded by
#     not(self::aaa) and                        #     a non-'aaa' node
#     not(following-sibling::aaa = current())   #     after the current node
#   ])
# ]

xsl_get_page = lxml.etree.XSLT(lxml.etree.XML('''\
  <xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

    <xsl:output method="xml" encoding="us-ascii" omit-xml-declaration="yes" />

    <xsl:param name="basename"/>
    <xsl:param name="path"/>

    <xsl:template match="/">
      <xsl:message><xsl:value-of select="concat('Got path: ', $path)"/></xsl:message>
      <xsl:variable name="id">
        <xsl:call-template name="path-to-id">
          <xsl:with-param name="p" select="$path"/>
        </xsl:call-template>
      </xsl:variable>
      <xsl:message><xsl:value-of select="concat('Got id: ', $id)"/></xsl:message>
      <xsl:comment>NEW PAGE</xsl:comment>
      <html>
        <body>
          <div id="{$id}">
            <xsl:apply-templates select="//div[@id = 'wikipage']/*"/>
          </div>
        </body>
      </html>
    </xsl:template>

    <xsl:template match="//div[contains(@class, 'wiki-toc')]"/>

    <xsl:template match="//span[@class = 'icon' and not(*)]"/>

    <xsl:template match="a[contains(@class, 'wiki') and
                           starts-with(@href, '/wiki/')]">
      <xsl:variable name="href">
        <xsl:call-template name="path-to-id">
          <xsl:with-param name="p" select="@href"/>
        </xsl:call-template>
      </xsl:variable>
      <a href="#{$href}">
        <xsl:apply-templates select="@*[name() != 'href']"/>
        <xsl:apply-templates/>
      </a>
    </xsl:template>

    <xsl:template match="a[starts-with(@href, '/attachment/wiki/')]">
      <a href="{concat($basename, @href)}">
        <xsl:apply-templates select="@*[name() != 'href']"/>
        <xsl:apply-templates/>
      </a>
    </xsl:template>

    <xsl:template match="img[starts-with(@src, '/raw-attachment/wiki/')]">
      <img src="{concat($basename, @src)}">
        <xsl:apply-templates select="@*[name() != 'src']"/>
        <xsl:apply-templates/>
      </img>
    </xsl:template>

    <xsl:template match="object[starts-with(@data, '/raw-attachment/wiki/') or
                                starts-with(@data, '/graphviz/')]">
      <object data="{concat($basename, @data)}">
        <xsl:apply-templates select="@*[name() != 'data']"/>
        <xsl:apply-templates/>
      </object>
    </xsl:template>

    <xsl:template match="embed[starts-with(@src, '/raw-attachment/wiki/') or
                               starts-with(@src, '/graphviz/')]">
      <embed src="{concat($basename, @src)}">
        <xsl:apply-templates select="@*[name() != 'src']"/>
        <xsl:apply-templates/>
      </embed>
    </xsl:template>

    <xsl:template match="text()[contains(., '&#8203;')]">
      <xsl:call-template name="remove-zero-width-spaces">
        <xsl:with-param name="s" select="."/>
      </xsl:call-template>
    </xsl:template>

    <xsl:template match="@*|node()">
      <xsl:copy>
        <xsl:copy-of select="@*"/>
        <xsl:apply-templates/>
      </xsl:copy>
    </xsl:template>

    <xsl:template name="path-to-id">
      <xsl:param name="p"/>
      <xsl:text>_</xsl:text>
      <xsl:call-template name="replace">
        <xsl:with-param name="s" select="$p"/>
        <xsl:with-param name="old">/</xsl:with-param>
        <xsl:with-param name="new">.</xsl:with-param>
      </xsl:call-template>
    </xsl:template>

    <xsl:template name="remove-zero-width-spaces">
      <xsl:param name="s"/>
      <xsl:call-template name="replace">
        <xsl:with-param name="s" select="$s"/>
        <xsl:with-param name="old">&#8203;</xsl:with-param>
        <xsl:with-param name="new"/>
      </xsl:call-template>
    </xsl:template>

    <xsl:template name="replace">
      <xsl:param name="s"/>
      <xsl:param name="old"/>
      <xsl:param name="new"/>
      <xsl:choose>
        <xsl:when test="contains($s, $old)">
          <xsl:call-template name="replace">
            <xsl:with-param name="s" select="concat(substring-before($s, $old),
                                                    $new,
                                                    substring-after($s, $old))"/>
            <xsl:with-param name="old" select="$old"/>
            <xsl:with-param name="new" select="$new"/>
          </xsl:call-template>
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="$s"/>
        </xsl:otherwise>
      </xsl:choose>       
    </xsl:template>

    <xsl:template match="ol">
      <xsl:if test="not(preceding-sibling::*[1]/self::ol)">
        <xsl:variable name="following" 
                      select="following-sibling::ol[
                                not(preceding-sibling::*[
                                  not(self::ol) and
                                  not(following-sibling::ol = current())
                                ])
                              ]"/>
        <xsl:copy>
          <xsl:apply-templates select="$following/@*[name() != 'start']"/>
          <xsl:apply-templates select="@*"/>
          <xsl:apply-templates select="node()"/>
          <xsl:apply-templates select="$following/node()"/>
        </xsl:copy>
      </xsl:if>
    </xsl:template>

  </xsl:transform>
'''))

# All the files we want to parse are HTML, so make HTML the default
# parser.  In theory the HTML produced by Trac is XHTML thus should
# parse correctly (in fact, better) as XML, but in practice this seems
# not to work properly at the moment, while parsing as HTML does.
# Haven't bothered to figure out why, life is too short.
#
# If you're reading this comment because this script stopped working
# after a Trac upgrade, try commenting out this line to see whether
# things have changed and Trac's HTML now parses better as XML.

lxml.etree.set_default_parser(lxml.etree.HTMLParser())

# Run the main program.
main()
