<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0">

<!-- $Id$ -->

<!-- import the main stylesheet -->
<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl"/>

<!-- create pdf bookmarks -->
<xsl:param name="fop.extensions" select="1"/>

<!-- use graphics for admons (note, tip, ...) -->
<xsl:param name="admon.graphics" select="1"/>
<xsl:param name="admon.graphics.path">graphics/</xsl:param>

<!-- use numbering for sections (not only for chapters) -->
<xsl:param name="section.autolabel" select="1"/>
<xsl:param name="section.label.includes.component.label" select="1"/>

<!-- include page numbers in cross references -->
<!-- <xsl:param name="insert.xref.page.number" select="1"/> -->

<!-- don't show URL's, but only the text of it -->
<xsl:param name="ulink.show" select="0"/>

<!-- put a page break after each section -->
<xsl:attribute-set name="section.level1.properties">
  <xsl:attribute name="break-after">page</xsl:attribute>
</xsl:attribute-set>

<!-- set link style to blue and underlined -->
<xsl:attribute-set name="xref.properties">
  <xsl:attribute name="color">blue</xsl:attribute>
  <xsl:attribute name="text-decoration">underline</xsl:attribute>
</xsl:attribute-set>

</xsl:stylesheet>
