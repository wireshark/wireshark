#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

include(FindCygwin)

if(ENABLE_PDF_GUIDES)
    find_package(FOP)
    if(${FOP_EXECUTABLE} STREQUAL "FOP_EXECUTABLE-NOTFOUND")
        message(FATAL_ERROR "fop wasn't found, but is necessary for building PDFs." )
    endif()
endif()

if(ENABLE_CHM_GUIDES)
    find_package(SED)
endif()

find_program(XSLTPROC_EXECUTABLE
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

if (WIN32 AND NOT "${CYGWIN_INSTALL_PATH}" STREQUAL "" AND ${XSLTPROC_EXECUTABLE} MATCHES "${CYGWIN_INSTALL_PATH}")
    FIND_PROGRAM(CYGPATH_EXECUTABLE
        NAMES cygpath
        PATHS ${CYGWIN_INSTALL_PATH}/bin
    )
    # XXX Duplicate of TO_A2X_COMPATIBLE_PATH
    MACRO( TO_XSLTPROC_COMPATIBLE_PATH _cmake_path _result )
        execute_process(
            COMMAND ${CYGPATH_EXECUTABLE} -u ${_cmake_path}
            OUTPUT_VARIABLE _cygwin_path
        )
        # cygpath adds a linefeed.
        string(STRIP "${_cygwin_path}" _cygwin_path)

        set( ${_result} ${_cygwin_path} )
    ENDMACRO()

    TO_XSLTPROC_COMPATIBLE_PATH( ${CMAKE_CURRENT_SOURCE_DIR} _xsltproc_current_source_dir )
    TO_XSLTPROC_COMPATIBLE_PATH( ${CMAKE_CURRENT_BINARY_DIR} _xsltproc_current_binary_dir )

    set ( _xsltproc_path "${_xsltproc_current_source_dir}:${_xsltproc_current_binary_dir}:${_xsltproc_current_binary_dir}/wsluarm_src")
else()
    set ( _xsltproc_path "${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/wsluarm_src")
endif()

# Translate XML to HTML
#XML2HTML(
#        wsug or wsdg
#        single-page or chunked
#        WSUG_FILES
#        WSUG_GRAPHICS
#)
MACRO(XML2HTML _target_dep _dir_pfx _mode _dbk_source _gfx_sources)
    # We depend on the docbook target to avoid parallel builds.
    SET(_dbk_dep ${_target_dep}_docbook)

    IF(${_mode} STREQUAL "chunked")
        SET(_basedir ${_dir_pfx}_html_chunked)
        SET(_STYLESHEET "http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl")
        SET(_modeparams --noout)
    ELSE() # single-page
        SET(_basedir ${_dir_pfx}_html)
        SET(_STYLESHEET "http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl")
        SET(_modeparams --output ${_basedir}/index.html)
    ENDIF()

    SET(_out_dir ${CMAKE_CURRENT_BINARY_DIR}/${_basedir})
    SET(_output ${_basedir}/index.html)

    FOREACH(_tmpgfx ${${_gfx_sources}})
        set(_gfx_deps ${CMAKE_CURRENT_SOURCE_DIR}/${_tmpgfx})
    ENDFOREACH()

#    GET_FILENAME_COMPONENT(_GFXDIR ${_gfx} ABSOLUTE)
#    GET_FILENAME_COMPONENT(_GFXDIR ${_GFXDIR} PATH)
#    GET_FILENAME_COMPONENT(_OUTDIR ${_output} PATH)
#    SET(_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/${_OUTDIR})

    SET(_gfx_dir ${_dir_pfx}_graphics)
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output}
        COMMAND ${CMAKE_COMMAND}
            -E make_directory ${_out_dir}
        COMMAND ${CMAKE_COMMAND}
           -E make_directory ${_out_dir}/${_gfx_dir}/toolbar
        COMMAND ${CMAKE_COMMAND}
           -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/${_gfx_dir} ${_out_dir}/${_gfx_dir}
        COMMAND ${CMAKE_COMMAND}
           -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/common_graphics ${_out_dir}/${_gfx_dir}
        COMMAND ${CMAKE_COMMAND}
           -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/${_gfx_dir}/toolbar ${_out_dir}/${_gfx_dir}/toolbar
        COMMAND ${CMAKE_COMMAND}
            -E copy ${CMAKE_CURRENT_SOURCE_DIR}/ws.css ${_out_dir}
        COMMAND ${XSLTPROC_EXECUTABLE}
            --path "${_xsltproc_path}"
            --stringparam base.dir ${_basedir}/
            ${_common_xsltproc_args}
            --stringparam admon.graphics.path ${_gfx_dir}/
            ${_modeparams}
            ${_STYLESHEET}
            ${_dbk_source}
        DEPENDS
            generate_${_dbk_source}
            ${_dbk_dep}
            ${_gfx_deps}
    )
    IF(NOT WIN32)
        ADD_CUSTOM_COMMAND(
            OUTPUT
                ${_output}
            COMMAND chmod
                -R og+rX ${_out_dir}
            APPEND
        )
    ENDIF()
ENDMACRO(XML2HTML)

# Translate XML to FO to PDF
#XML2PDF(
#       user-guide-a4.fo or user-guide-us.fo
#       WSUG_SOURCE
#       custom_layer_pdf.xsl
#       A4 or letter
#)
MACRO(XML2PDF _target_dep _output _dbk_source _stylesheet _paper)
    # We depend on the docbook target to avoid parallel builds.
    SET(_dbk_dep ${_target_dep}_docbook)
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output}
            ${_output}.fo
        COMMAND ${XSLTPROC_EXECUTABLE}
            --path "${_xsltproc_path}"
            --stringparam paper.type ${_paper}
            --stringparam img.src.path ${CMAKE_CURRENT_SOURCE_DIR}/
            --stringparam use.id.as.filename 1
            --stringparam admon.graphics 1
            --stringparam admon.graphics.path ${CMAKE_CURRENT_SOURCE_DIR}/common_graphics/
            --stringparam admon.graphics.extension .svg
            --nonet
            --output ${_output}.fo
            ${_stylesheet}
            ${_dbk_source}
        COMMAND ${FOP_EXECUTABLE}
            ${_output}.fo
            ${_output}
        DEPENDS
            generate_${_dbk_source}
            ${_dbk_dep}
            ${_stylesheet}
    )
ENDMACRO(XML2PDF)

# Translate XML to HHP
#XML2HHP(
#       wsug or wsdg
#       user-guide.xml or developer-guide.xml
#)
MACRO(XML2HHP _target_dep _guide _docbooksource)
    # We depend on the docbook target to avoid parallel builds.
    SET(_dbk_dep ${_target_dep}_docbook)
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
            ${_output_toc_hhc}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_basedir}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_basedir}/${_gfxdir}
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/${_gfxdir} ${_basedir}/${_gfxdir}
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/common_graphics ${_basedir}/${_gfxdir}
        # HTML Help doesn't render decimal character entities in the title.
        COMMAND ${SED_EXECUTABLE}
            -e "s|er&#8217;s Guide</title>|er's Guide</title>|"
            < ${_docbooksource}
            > ${_docbook_plain_title}
        COMMAND ${XSLTPROC_EXECUTABLE}
            --path "${_xsltproc_path}"
            --stringparam base.dir ${_basedir}/
            --stringparam htmlhelp.chm ${_output_chm}
            --stringparam htmlhelp.hhp ${_output_hhp}
            --stringparam htmlhelp.hhc ${_output_toc_hhc}
            ${_common_xsltproc_args}
            --stringparam admon.graphics.path ${_gfxdir}/
            --nonet custom_layer_chm.xsl
            ${_docbook_plain_title}
        DEPENDS
            generate_${_docbooksource}
            ${_dbk_dep}
            # AsciiDoc uses UTF-8 by default, which is unsupported by HTML
            # Help. We may want to render an ISO-8859-1 version, or get rid
            # of HTML Help.
            custom_layer_chm.xsl
    )
ENDMACRO(XML2HHP)
