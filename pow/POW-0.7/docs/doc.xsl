<?xml version="1.0"?>

<xsl:stylesheet 
   xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
   version="1.0"
>
   <xsl:template match="/">
      <book>
         <bookinfo>
            <title>The POW Package</title>
            <author><firstname>Peter</firstname> <surname>Shannon</surname></author>
         </bookinfo>
         <xsl:for-each select="collection/moduleSet">
            <xsl:call-template name="processModule"/>
         </xsl:for-each>
      </book>
   </xsl:template>

   <xsl:template name="processModule">
      <chapter>
         <title>The <xsl:value-of select="moduleDescription/header/name"/> Module</title>
         <sect1>
            <title>Introduction</title>
            <xsl:copy-of select="moduleDescription/body/*"/>
         </sect1>
         <xsl:if test="modulefunction">
            <sect1>
               <title>Module Functions</title>
               <xsl:call-template name="functionPrototypes"/>
               <xsl:call-template name="functionDescriptions"/>
            </sect1>
         </xsl:if>
         <sect1>
            <title>Module Classes</title>
            <xsl:call-template name="moduleClasses"/>
         </sect1>
      </chapter>
   </xsl:template>

   <xsl:template name="functionPrototypes">
      <sect2>
         <title>Function Prototypes</title>
         <funcsynopsis>
            <xsl:for-each select="modulefunction">
               <funcprototype>
                  <funcdef>def <function><xsl:value-of select="header/name"/></function></funcdef>
                  <xsl:call-template name="functionParameter"/>
               </funcprototype>
            </xsl:for-each>
         </funcsynopsis>
      </sect2>
   </xsl:template>

   <xsl:template name="functionDescriptions">
      <sect2>
         <title>Function Descriptions</title>
         <xsl:for-each select="modulefunction">
            <sect3>
               <title>The <function><xsl:value-of select="header/name"/></function> Function</title>

               <funcsynopsis>
                  <funcprototype>
                     <funcdef>def <function><xsl:value-of select="header/name"/></function></funcdef>
                     <xsl:call-template name="functionParameter"/>
                  </funcprototype>
               </funcsynopsis>

               <xsl:copy-of select="body/*"/>
            </sect3>
         </xsl:for-each>
      </sect2>
   </xsl:template>


   <xsl:template name="moduleClasses">
      <xsl:for-each select="class">
         <xsl:variable name="class">
            <xsl:value-of select="header/name"/>
         </xsl:variable>
         <sect2>
            <title>The <classname><xsl:value-of select="$class"/></classname> Class</title>

            <xsl:copy-of select="body/*"/>

            <sect3>
               <title>Class Prototypes</title> 
               <xsl:call-template name="methodPrototypes">
                  <xsl:with-param name="class">
                     <xsl:value-of select="$class"/>
                  </xsl:with-param>
               </xsl:call-template>
            </sect3> 

            <xsl:call-template name="methodDescriptions">
               <xsl:with-param name="class">
                  <xsl:value-of select="$class"/>
               </xsl:with-param>
            </xsl:call-template>

         </sect2>
      </xsl:for-each>
   </xsl:template>

   <xsl:template name="methodPrototypes">
      <xsl:param name="class"/>
      <classsynopsis>
         <xsl:attribute name="language">python</xsl:attribute>
         <ooclass><classname><xsl:value-of select="$class"/></classname></ooclass> 
         <xsl:if test="header/super">
            <xsl:for-each select="header/super">
               <ooclass><classname><xsl:value-of select="."/></classname></ooclass>
            </xsl:for-each>
         </xsl:if>
         <xsl:if test="..//header[memberof=$class]">
            <xsl:for-each select="../constructor[header/memberof=$class]">
               <constructorsynopsis>
                  <methodname><xsl:value-of select="$class"/></methodname> 
                  <xsl:call-template name="methodParameter"/>
               </constructorsynopsis> 
            </xsl:for-each>
            <xsl:for-each select="../method[header/memberof=$class]">
               <methodsynopsis>
                  <methodname><xsl:value-of select="header/name"/></methodname> 
                  <xsl:call-template name="methodParameter"/>
               </methodsynopsis> 
            </xsl:for-each>
         </xsl:if>
      </classsynopsis> 
   </xsl:template>

   <xsl:template name="functionParameter">
      <xsl:choose>
         <xsl:when test="header/parameter">
            <xsl:for-each select="header/parameter">
               <paramdef>
                  <parameter>
                     <xsl:value-of select="self::node()"/>
                  </parameter> 
               </paramdef> 
            </xsl:for-each>
         </xsl:when>
         <xsl:otherwise>
            <void/>
         </xsl:otherwise>
      </xsl:choose>
   </xsl:template>

   <xsl:template name="methodParameter">
      <xsl:choose>
         <xsl:when test="header/parameter">
            <xsl:for-each select="header/parameter">
               <methodparam>
                  <parameter>
                     <xsl:value-of select="self::node()"/>
                  </parameter> 
               </methodparam> 
            </xsl:for-each>
         </xsl:when>
         <xsl:otherwise>
            <void/>
         </xsl:otherwise>
      </xsl:choose>
   </xsl:template>

   <xsl:template name="methodDescriptions">
      <xsl:param name="class"/>

      <xsl:for-each select="../constructor[header/memberof=$class]">
         <xsl:if test="body">
            <sect3>
               <title>The <function>__init__</function> Method</title>
               <xsl:copy-of select="body/*"/>
            </sect3>
         </xsl:if>
      </xsl:for-each>

      <xsl:for-each select="../method[header/memberof=$class]">
         <xsl:if test="body">
            <sect3>
               <title>The <function><xsl:value-of select="header/name"/></function> Method</title>
               <xsl:copy-of select="body/*"/>
            </sect3>
         </xsl:if>
      </xsl:for-each>

   </xsl:template>

</xsl:stylesheet>
