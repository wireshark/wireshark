#
# $Id$
#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(XSLTPROC_EXECUTABLE
  NAMES
    xsltproc
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

# Handle the QUIETLY and REQUIRED arguments and set XSLTPROC_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(XSLTPROC DEFAULT_MSG XSLTPROC_EXECUTABLE)

MARK_AS_ADVANCED(XSLTPROC_EXECUTABLE)

#XML2HTML(
#       wsug.validated
#       wsug_html/user-guide.html
#       single-page
#       wsug_html
#       WSUG_SOURCE
#       WSUG_GFX_SOURCE
#)

# Translate xml to html
MACRO(XML2HTML _validated _output _mode _xmlsources _gfxsources)
    MESSAGE(STATUS "XML source(s): ${${_xmlsources}}")
    MESSAGE(STATUS "GFX source(s): ${${_gfxsources}}")
    
    GET_FILENAME_COMPONENT(_OUTDIR ${_output} PATH)
    IF(${_mode} STREQUAL "chunked")
    ELSE() # single-page
    ENDIF()

    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output}
        COMMAND
            cmake -E make_directory ${_OUTDIR}
        COMMAND
            cmake -E copy ${${_gfxsources}} ${_OUTDIR}
        COMMAND
            cmake -E copy ws.css ${_OUTDIR}
        DEPENDS
            ${${_xmlsources}}
            ${${_gfxsources}}
    )
#        mkdir -p wsug_html/wsug_graphics/toolbar
#        cp wsug_graphics/*.* wsug_html/wsug_graphics
#        cp wsug_graphics/toolbar/* wsug_html/wsug_graphics/toolbar
#        cp ws.css wsug_html

#        mkdir -p wsug_html_chunked/wsug_graphics/toolbar
#        cp wsug_graphics/*.* wsug_html_chunked/wsug_graphics
#        cp wsug_graphics/toolbar/* wsug_html_chunked/wsug_graphics/toolbar
#        cp ws.css wsug_html_chunked
ENDMACRO(XML2HTML)

#wsug_html/user-guide.html: $(WSUG_SOURCE)
#        @ echo --- WSUG - HTML SINGLE PAGE ---
#        mkdir -p wsug_html/wsug_graphics/toolbar
#        cp wsug_graphics/*.* wsug_html/wsug_graphics
#        cp wsug_graphics/toolbar/* wsug_html/wsug_graphics/toolbar
#        cp ws.css wsug_html
#        $(XSLTPROC) --stringparam base.dir wsug_html/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path wsug_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl $< > $@
#        -chmod -R og+rX wsug_html
#

#wsug_html_chunked/index.html: $(WSUG_SOURCE)
#        @ echo --- WSUG - HTML CHUNKED ---
#        mkdir -p wsug_html_chunked/wsug_graphics/toolbar
#        cp wsug_graphics/*.* wsug_html_chunked/wsug_graphics
#        cp wsug_graphics/toolbar/* wsug_html_chunked/wsug_graphics/toolbar
#        cp ws.css wsug_html_chunked
#        $(XSLTPROC) --stringparam base.dir wsug_html_chunked/ --stringparam  use.id.as.filename 1 --stringparam admon.graphics 1 --stringparam admon.graphics.path wsug_graphics/ --stringparam section.autolabel 1 --stringparam  section.label.includes.component.label 1 --stringparam html.stylesheet ws.css --nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl $<
#        -chmod -R og+rX wsug_html_chunked

#XML2PDF(
#       WSUG_SOURCE
#       custom_layer_pdf.xsl
#       A4
#)
#
#XML2PDF(
#       WSUG_SOURCE
#       custom_layer_pdf.xsl
#       letter
#)

#user-guide-us.fo: $(WSUG_SOURCE) custom_layer_pdf.xsl
#ifdef FOP
#        @ echo --- WSUG - PDF US PAPER ---
#        $(XSLTPROC) --stringparam paper.type letter --nonet custom_layer_pdf.xsl $< > $@
#endif
#
## create pdf file (through XSL-FO), portrait pages on A4 paper
## you will get lot's of errors, but that's ok
#user-guide-a4.fo: $(WSUG_SOURCE) custom_layer_pdf.xsl
#ifdef FOP
#        @ echo --- WSUG - PDF A4 PAPER ---
#        $(XSLTPROC) --stringparam paper.type A4 --nonet custom_layer_pdf.xsl $< > $@
#endif

