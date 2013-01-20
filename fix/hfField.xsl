<!--
-->

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:output method="text" encoding="UTF-8"/>

<xsl:template match="text()"/>

<xsl:template match="/">
static hf_register_info hf_FIX[] = {
<xsl:apply-templates/>
    };

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
</xsl:template>


<xsl:template match="fields">
<xsl:for-each select="field">
    <xsl:sort select="@number" data-type="number"/>
        { &amp;fix_fields[<xsl:value-of select="position( ) -1" />].hf_id,
            { "<xsl:value-of select="@name"/> (<xsl:value-of select="@number"/>)", "fix.<xsl:value-of select="@name"/>",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },</xsl:for-each></xsl:template>
</xsl:stylesheet>
