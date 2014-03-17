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

# Translate xml to html
#XML2HTML(
#        wsug.validated
#        wsug_html/user-guide.html or wsub_html/index.html
#        single-page or chunked
#        WSUG_FILES
#        WSUG_GRAPHICS
#)
MACRO(XML2HTML _validated _output _mode _xmlsources _gfxsources)
    FOREACH(_tmpgfx ${${_gfxsources}})
        set(_gfx ${_tmpgfx})
        BREAK()
    ENDFOREACH()
    GET_FILENAME_COMPONENT(_GFXDIR ${_gfx} ABSOLUTE)
    GET_FILENAME_COMPONENT(_GFXDIR ${_GFXDIR} PATH)
    GET_FILENAME_COMPONENT(_OUTDIR ${_output} PATH)
    SET(_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/${_OUTDIR})

    IF(${_mode} STREQUAL "chunked")
	SET(_STYLESHEET "http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl")
    ELSE() # single-page
	SET(_STYLESHEET "http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl")
    ENDIF()

    FOREACH(_tmpsource ${${_xmlsources}})
        set(_source ${_tmpsource})
        BREAK()
    ENDFOREACH()

    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output}
        COMMAND cmake
	    -E make_directory ${_OUTDIR}
	# Fixme: find out about subdirs (i.e. toolbar) automatically 
	#   so this works for wsdg as well.
#        COMMAND cmake
#	    -E make_directory ${_OUTDIR}/${_GFXDIR}/toolbar
#        COMMAND cp
#	    ${CMAKE_CURRENT_SOURCE_DIR}/${_GFXDIR}/*.* ${_OUTDIR}/${_GFXDIR}/
#        COMMAND cp
#	    ${CMAKE_CURRENT_SOURCE_DIR}/${_GFXDIR}/toolbar/*.* ${_OUTDIR}/${_GFXDIR}/toolbar/
        COMMAND cmake
	    -E copy ${CMAKE_CURRENT_SOURCE_DIR}/ws.css ${_OUTDIR}
	COMMAND ${XSLTPROC_EXECUTABLE}
	    --path "${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/wsluarm_src"
	    --stringparam img.src.path ${CMAKE_CURRENT_SOURCE_DIR}
	    --stringparam base.dir ${_OUTDIR}/
	    --stringparam use.id.as.filename 1
	    --stringparam admon.graphics 1
	    --stringparam admon.graphics.path ${_GFXDIR}/
	    --stringparam section.autolabel 1
	    --stringparam section.label.includes.component.label 1
	    --stringparam html.stylesheet ws.css
	    --nonet
            --output ${_output}
	    ${_STYLESHEET}
	    ${_source}
	COMMAND chmod
	    -R og+rX ${_OUTDIR}
        DEPENDS
	    ${_validated}
            ${${_xmlsources}}
            ${${_gfxsources}}
    )
ENDMACRO(XML2HTML)


#XML2PDF(
#	user-guide-a4.fo or user-guide-us.fo
#	WSUG_SOURCE
#	custom_layer_pdf.xsl
#	A4 or letter
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
	    --stringparam img.src.path ${CMAKE_CURRENT_SOURCE_DIR}
	    --stringparam base.dir ${_OUTDIR}/
	    --stringparam use.id.as.filename 1
	    --stringparam admon.graphics 1
	    --stringparam admon.graphics.path ${_GFXDIR}/
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

