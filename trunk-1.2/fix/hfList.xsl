<!--
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 <xsl:output method="text" encoding="UTF-8"/>

 <xsl:template match="text()"/>

 <xsl:template match="/">
      <xsl:apply-templates/>
</xsl:template>

<!--
   <xsl:value-of select="@number" />, <xsl:value-of select="@name" />, 
-->

<xsl:template match="fix">
<xsl:variable name="max_tag">
  <xsl:for-each select="fields/field/@number">
    <xsl:sort data-type="number" order="descending" />
      <xsl:if test="position() = 1">
      <xsl:value-of select="number(.)" />
      </xsl:if>
  </xsl:for-each>
</xsl:variable>#define FIX_<xsl:value-of select="@major"/><xsl:value-of select="@minor"/> <xsl:text> </xsl:text> 
<xsl:value-of select="$max_tag"/>
<xsl:text>
</xsl:text>
</xsl:template>

</xsl:stylesheet>
