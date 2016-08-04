<!-- 
 - XSL transform to extract useful content of a Trac Wiki page.
 -
 - Django generates weird HTML for ordered lists: it sometimes breaks
 - up a single ordered list into multiple adjacent <ol/> elements,
 - using the @start attribute to try to make the result look like a
 - single ordered list.  This looks OK in Firefox but confuses the
 - bejesus out of both html2markdown and htmldoc.  In some cases this is
 - probably unavoidable, but most of the uses of this I've seen look
 - gratuitous, and are probably the result of code modulararity issues
 - in Django.
 -
 - So we try to clean this up, by merging adjacent <ol/> elements where
 - we can.  The merge incantation is an adaptation of:
 -
 - http://stackoverflow.com/questions/1806123/merging-adjacent-nodes-of-same-type-xslt-1-0
 -
 - There may be a more efficient way to do this, but I don't think
 - we care, and this seems to work.
 -
 - Original author's explanation:
 -
 - The rather convoluted XPath expression for selecting the following
 - sibling aaa nodes which are merged with the current one:
 -
 - following-sibling::aaa[                       # following 'aaa' siblings
 -   not(preceding-sibling::*[                   #   if they are not preceded by
 -     not(self::aaa) and                        #     a non-'aaa' node
 -     not(following-sibling::aaa = current())   #     after the current node
 -   ])
 - ]
 -->

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

