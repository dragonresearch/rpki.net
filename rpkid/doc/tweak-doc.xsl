<!-- $Id$
  -
  - Suppress bits of HTML that we want filtered out before running
  - through lynx -dump to get flat text.
  -
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
  - Portions Copyright (C) 2008  American Registry for Internet Numbers ("ARIN")
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

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version='1.0'>

  <!--
    - Suppress navigational elements that have no place in flat text.
    -->
  <xsl:template match="div[@class = 'navigation' or @id = 'MSearchSelectWindow']"/>

  <!--
    - Add null p element after p element immediately followed by ul
    - element, or p element immediately followed by div element
    - containing verbatim fragment.  This is sick, but fakes lynx
    - into producing more reasonable output, which is all we really
    - care about here.
    -->
  <xsl:template match="p[(name(following-sibling::*[1]) = 'ul') or
                         (name(following-sibling::*[1]) = 'div' and
			  following-sibling::*[1]/@class = 'fragment')]">
    <p><xsl:apply-templates/></p>
    <p/>
  </xsl:template>

  <!--
    - Add delimiters around code examples.
    -->
  <xsl:template match="div[@class = 'fragment']" mode="disabled">
    <p>================================================================</p>
    <p/>
    <xsl:call-template name="identity"/>
    <p>================================================================</p>
  </xsl:template>

  <!--
    - Copy everything else unmodified (XSL "identity" template).
    -->
  <xsl:template match="node() | @*" name="identity">
    <xsl:copy>
      <xsl:apply-templates select="node() | @*"/>
    </xsl:copy>
  </xsl:template>
  
</xsl:stylesheet>
