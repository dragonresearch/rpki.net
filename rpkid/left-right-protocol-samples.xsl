<!--  -*- SGML -*-
  - $Id$
  -
  - Copyright (C) 2007-2008  American Registry for Internet Numbers ("ARIN")
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
  -
  -
  - Generate test case PDUs for left-right protocol.  Invoke thusly:
  -
  - $ xsltproc left-right-protocol-samples.xsl left-right-protocol-samples.xml
 --> 

<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
               xmlns:exsl="http://exslt.org/common"
	       extension-element-prefixes="exsl">

  <xsl:param name="dir">left-right-protocol-samples</xsl:param>
  <xsl:param name="msgs" select="1"/>

  <xsl:strip-space elements="*"/>

  <xsl:template match="/completely_gratuitous_wrapper_element_to_let_me_run_this_through_xmllint">
    <xsl:for-each select="*">
      <xsl:variable name="filename" select="concat($dir, '/pdu.', format-number(position(), '000'), '.xml')"/>
      <xsl:if test="$msgs">
        <xsl:message><xsl:text>Writing </xsl:text><xsl:value-of select="$filename"/></xsl:message>
      </xsl:if>
      <exsl:document href="{$filename}" indent="yes" encoding="US-ASCII">
        <xsl:comment>Automatically generated, do not edit.</xsl:comment>
        <xsl:copy-of select="." />
      </exsl:document>
    </xsl:for-each>
  </xsl:template>
</xsl:transform>
