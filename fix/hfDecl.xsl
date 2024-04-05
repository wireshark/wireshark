<!--
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 <xsl:output method="text" encoding="UTF-8"/>

 <xsl:template match="text()"/>

<xsl:template match="fields">
static const fix_field fix_fields[] = {
<xsl:for-each select="field">
    <xsl:sort select="@number" data-type="number"/>
    <xsl:choose>
           <xsl:when test="count( value ) != 0">
              <xsl:variable name="val_type" >
                  <xsl:choose>
                       <xsl:when test="@type='INT'">0</xsl:when>
                     <xsl:when test="@type='STRING'">1</xsl:when>
                    <xsl:otherwise>2</xsl:otherwise>
                  </xsl:choose>
                </xsl:variable>
        { <xsl:value-of select="@number"/>, <xsl:copy-of select="$val_type" />, <xsl:value-of select="@name"/>_val },</xsl:when>
          <xsl:otherwise>
        { <xsl:value-of select="@number"/>, 0, NULL }, /* <xsl:value-of select="@name"/> */</xsl:otherwise>
    </xsl:choose>
</xsl:for-each>
    };

<xsl:text>static int fix_hf[</xsl:text>
<xsl:value-of select="count( field )"/>
<xsl:text>];</xsl:text>
</xsl:template>
</xsl:stylesheet>
