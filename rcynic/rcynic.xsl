<?xml version="1.0"?>
<!--
  - Copyright (C) 2006  American Registry for Internet Numbers ("ARIN")
  -
  - Permission to use, copy, modify, and distribute this software for any
  - purpose with or without fee is hereby granted, provided that the above
  - copyright notice and this permission notice appear in all copies.
  -
  - THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
  - REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
  - AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
  - INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
  - LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
  - OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
  - PERFORMANCE OF THIS SOFTWARE.
 --> 

<!-- $Id$ -->

<!--
  - XSL stylesheet to render rcynic's xml-summary output as basic (X)HTML.
  - 
  - This is a bit more complicated than strictly necessary, because I wanted
  - the ability to drop out columns that are nothing but zeros.
  - There's probably some clever way of using XPath to simplify this,
  - but I don't expect the data sets to be large enough for performance
  - to be an issue here.   Feel free to show me how to do better.
 -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
		version="1.0"
                xmlns:exslt="http://exslt.org/common"
		exclude-result-prefixes="exslt">

  <xsl:output omit-xml-declaration="yes" indent="yes" method="xml" encoding="US-ASCII"/>

  <xsl:param name="suppress-zero-columns" select="1"/>

  <xsl:variable name="counts">
    <xsl:for-each select="rcynic-summary/labels/*">
      <x count="{count(/rcynic-summary/host/*[name() = name(current()) and . != 0])}"/>
    </xsl:for-each>
  </xsl:variable>

  <xsl:template match="/">
    <html>
      <xsl:variable name="title">
        <xsl:text>rcynic summary </xsl:text>
	<xsl:value-of select="rcynic-summary/@date"/>
      </xsl:variable>
      <head>
        <title>
	  <xsl:value-of select="$title"/>
	</title>
      </head>
      <body>
        <h1>
	  <xsl:value-of select="$title"/>
	</h1>
	<br/>
	<table rules="all">
	  <thead>
	    <tr>
	      <xsl:for-each select="rcynic-summary/labels/*">
	        <xsl:variable name="p" select="position()"/>
		<xsl:if test="$suppress-zero-columns = 0 or exslt:node-set($counts)/x[$p]/@count &gt; 0">
		  <td>
		    <b>
		      <xsl:apply-templates/>
		    </b>
		  </td>
		</xsl:if>
	      </xsl:for-each>
	    </tr>
	  </thead>
	  <tbody>
	    <xsl:for-each select="rcynic-summary/host">
	      <xsl:sort order="descending" data-type="number" select="sum(*[not(self::hostname)])"/>
	      <xsl:sort order="ascending" data-type="text" select="hostname"/>
	      <tr>
	        <xsl:for-each select="*">
		  <xsl:variable name="p" select="position()"/>
		  <xsl:if test="$suppress-zero-columns = 0 or exslt:node-set($counts)/x[$p]/@count &gt; 0">
		    <td>
		      <xsl:apply-templates/>
		    </td>
		  </xsl:if>
		</xsl:for-each>
	      </tr>
	    </xsl:for-each>
	  </tbody>
	</table>
      </body>
    </html>
  </xsl:template>

</xsl:stylesheet>

<!-- 
  - Local variables:
  - mode: sgml
  - End:
 -->
