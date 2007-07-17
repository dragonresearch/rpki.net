<!-- $Id$
  -
  - Generate test case PDUs for left-right protocol.  Invoke thusly:
  -
  - $ xsltproc left-right-protocol-samples.xsl ../docs/left-right-xml
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
