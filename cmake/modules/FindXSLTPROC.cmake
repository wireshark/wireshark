#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PACKAGE(SED)

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

set (_common_xsltproc_args
    --stringparam use.id.as.filename 1
    --stringparam admon.graphics 1
    --stringparam admon.graphics.extension .svg
    --stringparam section.autolabel 1
    --stringparam section.label.includes.component.label 1
    --stringparam html.stylesheet ws.css
    )

#set (WSUG_XSLTPROC_ARGS
#	--stringparam admon.graphics.path wsug_graphics/
#
#WSDG_XSLTPROC_ARGS = \
#	--stringparam admon.graphics.path wsdg_graphics/
#
#SINGLE_XSLTPROC_ARGS = \
#	--nonet http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl
#
#CHUNKED_XSLTPROC_ARGS = \
#	--nonet http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl
#
#HTMLHELP_XSLTPROC_ARGS = \
#

# Translate XML to HTML
#XML2HTML(
#        wsug or wsdg
#        single-page or chunked
#        WSUG_FILES
#        WSUG_GRAPHICS
#)
MACRO(XML2HTML _guide _mode _xmlsources _gfxsources)
    SET(_validated ${_guide}.validated)

    IF(${_mode} STREQUAL "chunked")
        SET(_basedir ${_guide}_html_chunked)
        SET(_STYLESHEET "http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl")
	SET(_modeparams --noout)
    ELSE() # single-page
        SET(_basedir ${_guide}_html)
        SET(_STYLESHEET "http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl")
	SET(_modeparams --output ${_basedir}/index.html)
    ENDIF()

    SET(_outdir ${CMAKE_CURRENT_BINARY_DIR}/${_basedir})
    SET(_output ${_basedir}/index.html)

#    FOREACH(_tmpgfx ${${_gfxsources}})
#        set(_gfx ${_tmpgfx})
#        BREAK()
#    ENDFOREACH()
#    GET_FILENAME_COMPONENT(_GFXDIR ${_gfx} ABSOLUTE)
#    GET_FILENAME_COMPONENT(_GFXDIR ${_GFXDIR} PATH)
#    GET_FILENAME_COMPONENT(_OUTDIR ${_output} PATH)
#    SET(_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/${_OUTDIR})

    FOREACH(_tmpsource ${${_xmlsources}})
        set(_source ${_tmpsource})
        BREAK()
    ENDFOREACH()

    SET(_gfxdir ${_guide}_graphics)
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output}
        COMMAND cmake
            -E make_directory ${_outdir}
        COMMAND cmake
           -E make_directory ${_outdir}/${_gfxdir}/toolbar
        COMMAND cp
           ${CMAKE_CURRENT_SOURCE_DIR}/${_gfxdir}/*.* ${_outdir}/${_gfxdir}/
        COMMAND cp
           ${CMAKE_CURRENT_SOURCE_DIR}/common_graphics/*.* ${_outdir}/${_gfxdir}/
        COMMAND cp
           ${CMAKE_CURRENT_SOURCE_DIR}/${_gfxdir}/toolbar/*.* ${_outdir}/${_gfxdir}/toolbar/
        COMMAND cmake
            -E copy ${CMAKE_CURRENT_SOURCE_DIR}/ws.css ${_outdir}
        COMMAND ${XSLTPROC_EXECUTABLE}
            --path "${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/wsluarm_src"
            --stringparam base.dir ${_basedir}/
	    ${_common_xsltproc_args}
            --stringparam admon.graphics.path ${_gfxdir}/
            ${_modeparams}
            ${_STYLESHEET}
            ${_source}
        COMMAND chmod
            -R og+rX ${_outdir}
        DEPENDS
            ${_validated}
            ${${_xmlsources}}
            ${${_gfxsources}}
    )
ENDMACRO(XML2HTML)

# Translate XML to FO to PDF
#XML2PDF(
#       user-guide-a4.fo or user-guide-us.fo
#       WSUG_SOURCE
#       custom_layer_pdf.xsl
#       A4 or letter
#)
MACRO(XML2PDF _output _sources _stylesheet _paper)
    FOREACH(_tmpsource ${${_sources}})
        set(_source ${_tmpsource})
        BREAK()
    ENDFOREACH()

    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output}
        COMMAND ${XSLTPROC_EXECUTABLE}
            --path "${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/wsluarm_src"
            --stringparam paper.type ${_paper}
            --stringparam img.src.path ${CMAKE_CURRENT_SOURCE_DIR}/
            --stringparam use.id.as.filename 1
            --stringparam admon.graphics 1
            --stringparam admon.graphics.path ${CMAKE_CURRENT_SOURCE_DIR}/common_graphics/
            --stringparam admon.graphics.extension .svg
            --nonet
            --output ${_output}.fo
            ${_stylesheet}
            ${_source}
        COMMAND ${FOP_EXECUTABLE}
            ${_output}.fo
            ${_output}
        DEPENDS
            ${${_sources}}
            ${_stylesheet}
    )
ENDMACRO(XML2PDF)

# Translate XML to HHP
#XML2HHP(
#       wsug or wsdg
#       user-guide.xml or developer-guide.xml
#)
MACRO(XML2HHP _guide _docbooksource)
    GET_FILENAME_COMPONENT( _source_base_name ${_docbooksource} NAME_WE )
    set( _output_chm ${_source_base_name}.chm )
    set( _output_hhp ${_source_base_name}.hhp )
    set( _output_toc_hhc ${_source_base_name}-toc.hhc )
    set( _docbook_plain_title ${_source_base_name}-plain-title.xml )

    SET(_gfxdir ${_guide}_graphics)
    SET(_basedir ${_guide}_chm)
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output_hhp}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${_basedir}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${_basedir}/${_gfxdir}
	COMMAND ${CMAKE_COMMAND} -E copy_directory ${_gfxdir} ${_basedir}/${_gfxdir}
	COMMAND ${CMAKE_COMMAND} -E copy_directory common_graphics ${_basedir}
	COMMAND ${SED_EXECUTABLE}
	    -e "s|er&#8217;s Guide</title>|er's Guide</title>|"
	    < ${_docbooksource}
	    > ${_docbook_plain_title}
        COMMAND ${XSLTPROC_EXECUTABLE}
            --path "${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/wsluarm_src"
            --stringparam base.dir ${_basedir}/
	    --stringparam htmlhelp.chm ${_output_chm}
	    --stringparam htmlhelp.hhp ${_output_hhp}
	    --stringparam htmlhelp.hhc ${_output_toc_hhc}
	    ${_common_xsltproc_args}
            --stringparam admon.graphics.path ${_gfxdir}/
	    --nonet custom_layer_chm.xsl
	    ${_docbook_plain_title}
        DEPENDS
            ${_docbooksource}
    )
ENDMACRO(XML2HHP)
