<?xml version="1.0"?>
<!--
  - Copyright (C) 2010-2011  Internet Systems Consortium, Inc. ("ISC")
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
                xmlns:com="http://exslt.org/common"
		xmlns:str="http://exslt.org/strings"
		exclude-result-prefixes="com str">

  <xsl:output omit-xml-declaration="yes" indent="yes" method="xml" encoding="US-ASCII"
              doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
	      doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"/>

  <xsl:param	name="refresh"			select="1800"/>
  <xsl:param	name="suppress-zero-columns"	select="1"/>
  <xsl:param	name="show-total"		select="1"/>
  <xsl:param	name="use-colors"		select="1"/>
  <xsl:param	name="show-detailed-status"	select="1"/>
  <xsl:param	name="show-problems"		select="0"/>
  <xsl:param	name="show-summary"		select="1"/>

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
		td	{ text-align: center; padding: 4px }
		td.uri	{ text-align: left }
	  <xsl:if test="$use-colors != 0">
		tr.good	{ background-color: #77ff77 }
		tr.warn	{ background-color: yellow }
		tr.bad	{ background-color: #ff5500 }
	  </xsl:if>
	</style>
      </head>
      <body>


        <h1><xsl:value-of select="$title"/></h1>

        <!-- Summary output, old host-oriented format -->
	<xsl:if test="$show-summary != 0">

	  <!-- Collect data we need to display -->
	  <xsl:variable name="host-data">
	    <xsl:for-each select="rcynic-summary/validation_status">
	      <xsl:sort order="ascending" data-type="text" select="."/>
	      <xsl:variable name="uri" select="string(.)"/>
	      <xsl:if test="starts-with($uri, 'rsync://')">
		<xsl:variable name="hostname" select="str:tokenize($uri, ':/')[2]"/>
		<xsl:variable name="mood" select="/rcynic-summary/labels/*[name() = current()/@status]/@kind"/>
		<xsl:variable name="fn2">
		  <xsl:if test="substring($uri, string-length($uri) - 3, 1) = '.'">
		    <xsl:value-of select="substring($uri, string-length($uri) - 3)"/>
		  </xsl:if>
		</xsl:variable>
		<x hostname="{$hostname}" timestamp="{@timestamp}" uri="{$uri}" status="{@status}" mood="{$mood}" fn2="{$fn2}"/>
	      </xsl:if>
	    </xsl:for-each>
	  </xsl:variable>

	  <!-- Calculate set of unique hostnames -->
	  <xsl:variable name="unique-hostnames">
	    <xsl:for-each select="com:node-set($host-data)/x[not(@hostname = following::x/@hostname)]">
	      <x hostname="{@hostname}"/>
	    </xsl:for-each>
	  </xsl:variable>

	  <!-- Calculate set of unique filename types -->
	  <xsl:variable name="unique-fn2s">
	    <xsl:for-each select="com:node-set($host-data)/x[not(@fn2 = following::x/@fn2)]">
	      <x fn2="{@fn2}"/>
	    </xsl:for-each>
	  </xsl:variable>

	  <!-- Calculate totals, figure out which columns to display -->
	  <xsl:variable name="totals">
	    <xsl:for-each select="rcynic-summary/labels/*">
	      <xsl:variable name="sum" select="count(com:node-set($host-data)/x[@status = name(current())])"/>
	      <xsl:variable name="show">
		<xsl:choose>
		  <xsl:when test="$suppress-zero-columns = 0 or $sum &gt; 0">
		    <xsl:text>1</xsl:text>
		  </xsl:when>
		  <xsl:otherwise>
		    <xsl:text>0</xsl:text>
		  </xsl:otherwise>
		</xsl:choose>
	      </xsl:variable>
	      <x name="{name(current())}" sum="{$sum}" text="{.}" show="{$show}"/>
	    </xsl:for-each>
	  </xsl:variable>

	  <!-- Temporary hack -->
	  <br/>
	  <h2>[TEST] Filename extensions</h2>
	  <table>
	    <thead>
	      <tr>
		<td>Extension</td>
	      </tr>
	    </thead>
	    <tbody>
	      <xsl:for-each select="com:node-set($unique-fn2s)/x">
		<xsl:sort order="ascending" data-type="text" select="@fn2"/>
		<tr>
		  <td>
		    <xsl:value-of select="concat('&quot;', @fn2, '&quot;')"/>
		  </td>
		</tr>
	      </xsl:for-each>
	    </tbody>
	  </table>

	  <!-- Generate the HTML -->
	  <br/>
	  <h2>Summary by Repository Host</h2>
	  <table class="summary" rules="all">
	    <thead>
	      <tr>
	        <td><b>Publication Repository</b></td>
		<xsl:for-each select="com:node-set($totals)/x[@show = 1]">
		  <td><b><xsl:value-of select="@text"/></b></td>
		</xsl:for-each>
	      </tr>
	    </thead>
	    <tbody>
	      <xsl:for-each select="com:node-set($unique-hostnames)/x">
		<xsl:sort order="ascending" data-type="text" select="."/>
		<xsl:variable name="hostname" select="@hostname"/>
		<xsl:variable name="goodness" select="count(com:node-set($host-data)/x[@hostname = $hostname and @mood = 'good'])"/>
		<xsl:variable name="badness"  select="count(com:node-set($host-data)/x[@hostname = $hostname and @mood = 'bad'])"/>
		<xsl:variable name="warnings" select="count(com:node-set($host-data)/x[@hostname = $hostname and @mood = 'warn'])"/>
		<xsl:variable name="mood">
		  <xsl:choose>
		    <xsl:when test="$goodness != 0 and $warnings = 0 and $badness = 0">good</xsl:when>
		    <xsl:when test="$goodness + $warnings != 0">warn</xsl:when>
		    <xsl:otherwise>bad</xsl:otherwise>
		  </xsl:choose>
		</xsl:variable>
		<tr class="{$mood}">
		  <td><xsl:value-of select="$hostname"/></td>
		  <xsl:for-each select="com:node-set($totals)/x[@show = 1]">
		    <xsl:variable name="label" select="@name"/>
		    <xsl:variable name="value" select="count(com:node-set($host-data)/x[@hostname = $hostname and @status = $label])"/>
		    <td>
		      <xsl:if test="$value != 0">
		        <xsl:value-of select="$value"/>
		      </xsl:if>
		      </td>
		  </xsl:for-each>
		</tr>
	      </xsl:for-each>
	      <xsl:if test="$show-total != 0">
		<tr>
		  <td><b>Total</b></td>
		  <xsl:for-each select="com:node-set($totals)/x">
		    <xsl:if test="$suppress-zero-columns = 0 or @sum &gt; 0">
		      <td><b><xsl:value-of select="@sum"/></b></td>
		    </xsl:if>
		  </xsl:for-each>
		</tr>
	      </xsl:if>
	    </tbody>
	  </table>
	</xsl:if>

	<!-- "Problems" display -->
	<xsl:if test="$show-problems != 0">
	  <br/>
	  <h2>Problems</h2>
	  <table class="problems" rules="all" >
	    <thead>
	      <tr>
		<td class="status"><b>Status</b></td>
		<td class="uri"><b>URI</b></td>
	      </tr>
	    </thead>
	    <tbody>
	      <xsl:for-each select="rcynic-summary/validation_status">
		<xsl:variable name="status" select="@status"/>
		<xsl:variable name="mood" select="/rcynic-summary/labels/*[name() = $status]/@kind"/>
		<xsl:if test="$mood != 'good'">
		  <tr class="{$mood}">
		    <td class="status"><xsl:value-of select="/rcynic-summary/labels/*[name() = $status] "/></td>
		    <td class="uri"><xsl:value-of select="."/></td>
		  </tr>
		</xsl:if>
	      </xsl:for-each>
	    </tbody>
	  </table>
	</xsl:if>

	<!-- Detailed status display -->
	<xsl:if test="$show-detailed-status != 0">
	  <br/>
	  <h2>Validation Status</h2>
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
		<xsl:variable name="mood" select="/rcynic-summary/labels/*[name() = $status]/@kind"/>
		<tr class="{$mood}">
		  <td class="timestamp"><xsl:value-of select="@timestamp"/></td>
		  <td class="status"><xsl:value-of select="/rcynic-summary/labels/*[name() = $status] "/></td>
		  <td class="uri"><xsl:value-of select="."/></td>
		</tr>
	      </xsl:for-each>
	    </tbody>
	  </table>
	</xsl:if>

      </body>
    </html>
  </xsl:template>

</xsl:stylesheet>

<!-- 
  - Local variables:
  - mode: sgml
  - End:
 -->
