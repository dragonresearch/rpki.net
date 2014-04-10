<!--  -*- SGML -*-
  - $Id$
  -
  - Copyright (C) 2009  Internet Systems Consortium ("ISC")
  -
  - Permission to use, copy, modify, and distribute this software for any
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
 --> 

<!--
  - Split Base64 XML text elements into reasonable length chunks, to
  - make the result more readable, allow halfway-sane comparisions of
  - XML using diff, etc.  Makes no attempt to distinguish Base64 from
  - other text, so not suitable for use on XML with text elements that
  - are -not- Base64.  Piping output of this transform into xmlindent
  - produces something halfway readable.  YMMV.
 --> 

<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:output method="xml"/>

  <xsl:param name="width" select="64"/>

  <xsl:template match="text()">
    <xsl:text>&#10;</xsl:text>
    <xsl:call-template name="wrap">
      <xsl:with-param name="input" select="translate(normalize-space(), ' ', '')"/>
    </xsl:call-template>
  </xsl:template>

  <xsl:template match="node()|@*">
    <xsl:copy>
      <xsl:copy-of select="@*"/>
      <xsl:apply-templates/>
    </xsl:copy>
  </xsl:template>

  <xsl:template name="wrap">
    <xsl:param name="input"/>
    <xsl:text>            </xsl:text>
    <xsl:choose>
      <xsl:when test="string-length($input) > $width">
        <xsl:value-of select="substring($input, 1, $width)"/>
	<xsl:text>&#10;</xsl:text>
	<xsl:call-template name="wrap">
	  <xsl:with-param name="input" select="substring($input, $width+1)"/>
	</xsl:call-template>
      </xsl:when>
      <xsl:otherwise>
        <xsl:value-of select="$input"/>
	<xsl:text>&#10;</xsl:text>
      </xsl:otherwise>
    </xsl:choose>
  </xsl:template>

</xsl:transform>
