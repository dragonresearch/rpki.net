<?xml version="1.0"?>
<!--
  - Copyright (C) 2010  Internet Systems Consortium, Inc. ("ISC")
  -
  - Permission to use, copy, modify, and/or distribute this software for any
  - purpose with or without fee is hereby granted, provided that the above
  - copyright notice and this permission notice appear in all copies.
  -
  - THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
  - REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
  - AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
  - INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
  - LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
  - OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
  - PERFORMANCE OF THIS SOFTWARE.
  -
  - Portions copyright (C) 2006  American Registry for Internet Numbers ("ARIN")
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

  <xsl:output omit-xml-declaration="yes" indent="yes" method="xml" encoding="US-ASCII"
              doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
	      doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"/>

  <xsl:param name="suppress-zero-columns" select="1"/>

  <xsl:param name="refresh" select="1800"/>

  <xsl:param name="show-total" select="1"/>

  <xsl:variable name="sums">
    <xsl:for-each select="rcynic-summary/labels/*">
      <x sum="{sum(/rcynic-summary/host/*[name() = name(current()) and . != 0])}"/>
    </xsl:for-each>
  </xsl:variable>

  <xsl:template match="/">
    <xsl:comment>Generators</xsl:comment>
    <xsl:comment><xsl:value-of select="rcynic-summary/@rcynic-version"/></xsl:comment>
    <xsl:comment>$Id$</xsl:comment>
    <html>
      <xsl:variable name="title">
        <xsl:text>rcynic summary </xsl:text>
	<xsl:value-of select="rcynic-summary/@date"/>
      </xsl:variable>
      <head>
        <title>
	  <xsl:value-of select="$title"/>
	</title>
	<xsl:if test="$refresh != 0">
	  <meta http-equiv="Refresh" content="{$refresh}"/>
	</xsl:if>
	<style type="text/css">
	    td		{ text-align: center; padding: 4px }
	    td.uri	{ text-align: left }
	    tr.happy	{ background-color: #77ff77 }
	    tr.warning	{ background-color: yellow }
	    tr.danger	{ background-color: #ff5500 }
	</style>
      </head>
      <body>
        <h1>
	  <xsl:value-of select="$title"/>
	</h1>
	<table class="summary" rules="all">
	  <thead>
	    <tr>
	      <xsl:for-each select="rcynic-summary/labels/*">
	        <xsl:variable name="p" select="position()"/>
		<xsl:if test="$suppress-zero-columns = 0 or position() = 1 or exslt:node-set($sums)/x[$p]/@sum &gt; 0">
		  <td><b><xsl:apply-templates/></b></td>
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
		  <xsl:if test="$suppress-zero-columns = 0 or position() = 1 or exslt:node-set($sums)/x[$p]/@sum &gt; 0">
		    <td><xsl:if test=". != 0"><xsl:apply-templates/></xsl:if></td>
		  </xsl:if>
		</xsl:for-each>
	      </tr>
	    </xsl:for-each>
	    <xsl:if test="$show-total != 0">
	      <tr>
		<td><b>Total</b></td>
		<xsl:for-each select="exslt:node-set($sums)/x[position() &gt; 1]">
		  <xsl:if test="$suppress-zero-columns = 0 or @sum &gt; 0">
		    <td><b><xsl:value-of select="@sum"/></b></td>
		  </xsl:if>
		</xsl:for-each>
	      </tr>
	    </xsl:if>
	  </tbody>
	</table>
	<br/>
	<h1>Validation Status</h1>
	<table class="details" rules="all" >
	  <thead>
	    <tr>
	      <td class="timestamp"><b>Timestamp</b></td>
	      <td class="status"><b>Status</b></td>
	      <td class="uri"><b>URI</b></td>
	    </tr>
	  </thead>
	  <tbody>
	    <xsl:for-each select="rcynic-summary/validation_status">
	      <xsl:variable name="status" select="@status"/>
	      <xsl:variable name="mood">
	        <xsl:choose>
		  <xsl:when test="$status = 'validation_ok'">happy</xsl:when>
		  <xsl:otherwise>danger</xsl:otherwise>
	        </xsl:choose>
	      </xsl:variable>
	      <tr class="{$mood}">
	        <td class="timestamp"><xsl:value-of select="@timestamp"/></td>
		<td class="status"><xsl:value-of select="/rcynic-summary/labels/*[name() = $status] "/></td>
		<td class="uri"><xsl:value-of select="."/></td>
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
