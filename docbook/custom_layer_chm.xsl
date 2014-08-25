<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version="1.0">

<!-- copied from custom_layer_pdf.xsl -->

<!-- import the main stylesheet -->
<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/htmlhelp/htmlhelp.xsl"/>

<!-- use graphics for admons (note, tip, ...)
<xsl:param name="admon.graphics" select="1"/>
<xsl:param name="admon.graphics.path">common_graphics/</xsl:param>
<xsl:param name="admon.graphics.extension" select="'.svg'"/>
-->

<!--
  Tell the WebBrowser control to use the IE9 rendering engine if present so
  that our admonition graphics (which are SVG) show up. We might be able to
  get away with "IE=8" if needed.
  http://stackoverflow.com/questions/4612255/regarding-ie9-webbrowser-control/4613025#4613025
-->
<xsl:template name="system.head.content">
  <meta http-equiv="X-UA-Compatible" content="IE=9" />
</xsl:template>

<xsl:template name="user.head.content">
  <style type="text/css">
  html body, h1, h2, h3, h4, h5, h6,
  div.toc p b,
  div.list-of-figures p b,
  div.list-of-tables p b,
  div.abstract p.title
  {
    font-family: 'Segoe UI', 'Lucida Grande', Verdana, Arial, Helvetica, sans-serif;
    font-size: 14px;
  }
  </style>
</xsl:template>

<!-- reduce the size of programlisting to make them fit the page -->
<xsl:attribute-set name="monospace.verbatim.properties">
  <xsl:attribute name="font-size">80%</xsl:attribute>
</xsl:attribute-set>

</xsl:stylesheet>
