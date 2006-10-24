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
 -->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:output omit-xml-declaration="yes" indent="yes" method="xml" encoding="US-ASCII"/>

  <xsl:template match="/">
    <html>
      <head>
        <title>rcynic summary</title>
      </head>
      <body>
        <h1>rcynic summary</h1>
	<br/>
	<xsl:apply-templates/>
      </body>
    </html>
  </xsl:template>

  <xsl:template match="/rcynic-summary">
    <table rules="all">
      <thead>
	<xsl:apply-templates select="labels"/>
      </thead>
      <tbody>
	<xsl:apply-templates select="host"/>
      </tbody>
    </table>
  </xsl:template>

  <xsl:template match="/rcynic-summary/*">
    <tr>
      <xsl:apply-templates/>    
    </tr>
  </xsl:template>

  <xsl:template match="/rcynic-summary/labels/*">
    <td>
      <b>
        <xsl:apply-templates/>
      </b>
    </td>
  </xsl:template>

  <xsl:template match="/rcynic-summary/host/*">
    <td>
      <xsl:apply-templates/>
    </td>
  </xsl:template>

</xsl:stylesheet>

<!-- 
  - Local variables:
  - mode: sgml
  - End:
 -->
