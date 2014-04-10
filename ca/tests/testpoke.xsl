<!--  -*- SGML -*-
  - $Id$
  -
  - Copyright (C) 2008  American Registry for Internet Numbers ("ARIN")
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

<!--
  - Decoder ring for testpoke.py XML output.  Use this to get a
  - (somewhat) human-readable listing and to put OpenSSL-style
  - delimiters onto the certificates so that "openssl x509" can read
  - the result.  With a tad more work, we could select just one out of
  - the set of multiple certificates, or output YAML.  For the moment,
  - I'll settle for being readable by human beings and OpenSSL.
 --> 

<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
	       xmlns:rpkiud="http://www.apnic.net/specs/rescerts/up-down/">

  <xsl:output method="text"/>

  <xsl:param name="show-issuer" select="0"/>

  <xsl:template match="/rpkiud:message[@type = 'list_response']">
    <xsl:value-of select="concat('[Message]',                 '&#10;',
                                 'Version:     ', @version,   '&#10;',
                                 'Sender:      ', @sender,    '&#10;',
				 'Recipient:   ', @recipient, '&#10;')"/>
    <xsl:apply-templates select="rpkiud:class"/>
  </xsl:template>

  <xsl:template match="rpkiud:class">
    <xsl:value-of select="concat('&#10;',
				 '[Class]',                               '&#10;',
				 'Name:        ', @class_name,            '&#10;',
                                 'Issuer URL:  ', @cert_url,              '&#10;',
				 'ASNs:        ', @resource_set_as,       '&#10;',
				 'IPv4:        ', @resource_set_ipv4,     '&#10;',
				 'IPv6:        ', @resource_set_ipv6,     '&#10;',
				 'NotAfter:    ', @resource_set_notafter, '&#10;',
				 'SIA head:    ', @suggested_sia_head,    '&#10;')"/>
    <xsl:if test="$show-issuer">
      <xsl:apply-templates select="rpkiud:issuer"/>
    </xsl:if>
    <xsl:apply-templates select="rpkiud:certificate"/>
  </xsl:template>

  <xsl:template match="rpkiud:certificate">
    <xsl:value-of select="concat('&#10;',
                                 '[Certificate]',                     '&#10;',
				 'Subject URL: ', @cert_url,          '&#10;',
				 'Req ASNs:    ', @resource_set_as,   '&#10;',
				 'Req IPv4:    ', @resource_set_ipv4, '&#10;',
				 'Req IPv6:    ', @resource_set_ipv6, '&#10;')"/>
    <xsl:call-template name="show-pem"/>
  </xsl:template>

  <xsl:template match="rpkiud:issuer" name="show-pem">
    <xsl:text>&#10;</xsl:text>
    <xsl:text>-----BEGIN CERTIFICATE-----</xsl:text>
    <xsl:text>&#10;</xsl:text>
    <xsl:value-of select="text()"/>
    <xsl:text>-----END CERTIFICATE-----</xsl:text>
    <xsl:text>&#10;</xsl:text>
  </xsl:template>

</xsl:transform>
