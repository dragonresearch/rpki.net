<!-- $Id$ -->
<!--
  - Translate between old "myrpki" XML and current IETF standards
  - track out-of-band-setup protocol XML.  Well, partially.  Much of
  - the old protocol is either irrelevant or can't be translated due
  - to embedded signatures, but the subset that other implementations
  - implement is small enough that we can fake something workable.
  -->

<xsl:transform xmlns:xsl    = "http://www.w3.org/1999/XSL/Transform"
	       xmlns:myrpki = "http://www.hactrn.net/uris/rpki/myrpki/"
	       xmlns:oob    = "http://www.hactrn.net/uris/rpki/rpki-setup/"
	       version      = "1.0">

  <xsl:output omit-xml-declaration = "yes"
	      indent               = "yes"
	      method               = "xml"
	      encoding             = "US-ASCII"/>

  <!-- Versions of the respective protocols -->

  <xsl:param name = "myrpki-version"  select = "2"/>
  <xsl:param name = "oob-version"     select = "1"/>

  <!-- Translate an old-style identity to a new-style child_request -->

  <xsl:template match = "/myrpki:identity">
    <oob:child_request version = "{$oob-version}" child_handle = "{@handle}">
      <oob:child_bpki_ta>
	<xsl:value-of select = "myrpki:bpki_ta"/>
      </oob:child_bpki_ta>
    </oob:child_request>
  </xsl:template>

  <!-- Translate a new-style child_request to an old style identity -->

  <xsl:template match = "/oob:child_request">
    <myrpki:identity version = "{$myrpki-version}" handle = "{@child_handle}">
      <myrpki:bpki_ta>
	<xsl:value-of select = "oob:child_bpki_ta"/>
      </myrpki:bpki_ta>
    </myrpki:identity>
  </xsl:template>

  <!-- Translate an old-style parent response to a new-style parent_response -->
  <!-- Referrals are not translatable due to embedded signatures -->

  <xsl:template match = "/myrpki:parent">
    <oob:parent_response version       = "{$oob-version}"
			 service_uri   = "{@service_uri}"
			 child_handle  = "{@child_handle}"
			 parent_handle = "{@parent_handle}">
      <oob:parent_bpki_ta>
	<xsl:value-of select = "myrpki:bpki_resource_ta"/>
      </oob:parent_bpki_ta>
      <xsl:if test = "repository[@type = 'offer']">
	<oob:offer/>
      </xsl:if>
    </oob:parent_response>
  </xsl:template>

  <!-- Translate a new-style parent_response to an old-style parent response -->
  <!-- Referrals are not translatable due to embedded signatures -->

  <xsl:template match = "/oob:parent_response">
    <myrpki:parent version       = "{$myrpki-version}"
		   service_uri   = "{@service_uri}"
		   child_handle  = "{@child_handle}"
		   parent_handle = "{@parent_handle}">
      <myrpki:bpki_resource_ta>
	<xsl:value-of select = "oob:parent_bpki_ta"/>
      </myrpki:bpki_resource_ta>
      <myrpki:bpki_child_ta/>
      <myrpki:repository type = "none"/>
    </myrpki:parent>
  </xsl:template>

</xsl:transform>
