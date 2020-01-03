#
# - Find XSLTPROC
# This module looks for some usual Unix commands.
#

include(FindChocolatey)

# Strawberry Perl ships with xsltproc but no DocBook XML files, which
# is detrimental to our interests. Search for the Chocolatey
# versions first, and un-find xsltproc if needed.
find_program(XSLTPROC_EXECUTABLE
  NAMES
    xsltproc
  HINTS
    ${CHOCOLATEY_BIN_PATH}
  PATHS
    /usr/local/bin
    /sbin
)

string(TOLOWER ${XSLTPROC_EXECUTABLE} _xe_lower)
if(${_xe_lower} MATCHES "strawberry")
	set(_ignore_reason "Strawberry xsltproc found at ${XSLTPROC_EXECUTABLE}. Ignoring.")
	message(STATUS ${_ignore_reason})
	set(XSLTPROC_EXECUTABLE XSLTPROC_EXECUTABLE-NOTFOUND CACHE FILEPATH ${_ignore_reason} FORCE)
endif()

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

set(_xsltproc_path "${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/wsluarm_src")

# Workaround for parallel build issue with msbuild.
# https://gitlab.kitware.com/cmake/cmake/issues/16767
if(CMAKE_GENERATOR MATCHES "Visual Studio")
  # msbuild (as used by the Visual Studio generators) must not depend on the XML
  # file (otherwise the XML file will be generated multiple times, possibly in
  # parallel, breaking the build). Workaround: add one dependency to generate
  # the XML file when outdated, depend on the -stamp file to ensure that the
  # target is rebuilt when the XML file is regenerated.
  function(get_docbook_xml_depends varname _dbk_source)
    set(${varname}
      "generate_${_dbk_source}"
      "${CMAKE_CURRENT_BINARY_DIR}/${_dbk_source}-stamp"
      PARENT_SCOPE
    )
  endfunction()
else()
  # Unix Makefiles, Ninja, etc: first dependency enforces that the XML file is
  # rebuilt when outdated, the second dependency ensures that the target is
  # rebuilt when the XML file has changed.
  function(get_docbook_xml_depends varname _dbk_source)
    set(${varname}
      "generate_${_dbk_source}"
      "${_dbk_source}"
      PARENT_SCOPE
    )
  endfunction()
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

    # We can pass chunker.xxx parameters to customize the chunked output.
    # We have to use a custom layer to customize the single-page output.
    # Set the output encoding for both to UTF-8. Indent the single-page
    # output because we sometimes need to copy and paste the release
    # note contents.
    IF(${_mode} STREQUAL "chunked")
        SET(_basedir ${_dir_pfx}_html_chunked)
        SET(_stylesheet "http://docbook.sourceforge.net/release/xsl/current/html/chunk.xsl")
        SET(_modeparams --stringparam chunker.output.encoding UTF-8)
    ELSE() # single-page
        SET(_basedir ${_dir_pfx}_html)
        SET(_stylesheet custom_layer_single_html.xsl)
        SET(_modeparams --output ${_basedir}/index.html)
    ENDIF()

    SET(_out_dir ${CMAKE_CURRENT_BINARY_DIR}/${_basedir})
    SET(_output ${_basedir}/index.html)
    get_docbook_xml_depends(_dbk_xml_deps "${_dbk_source}")

    FOREACH(_tmpgfx ${${_gfx_sources}})
        set(_gfx_deps ${CMAKE_CURRENT_SOURCE_DIR}/${_tmpgfx})
    ENDFOREACH()

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
            -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/ws.css ${_out_dir}
        COMMAND ${XSLTPROC_EXECUTABLE}
            --path "${_xsltproc_path}"
            --stringparam base.dir ${_basedir}/
            ${_common_xsltproc_args}
            --stringparam admon.graphics.path ${_gfx_dir}/
            ${_modeparams}
            --noout ${_stylesheet}
            ${_dbk_source}
        DEPENDS
            ${_dbk_xml_deps}
            ${_dbk_dep}
            ${_gfx_deps}
            custom_layer_single_html.xsl
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

# Translate XML to HHP
#XML2HHP(
#       wsug or wsdg
#       user-guide.xml or developer-guide.xml
#)
MACRO(XML2HHP _target_dep _guide _title _dbk_source)
    # We depend on the docbook target to avoid parallel builds.
    SET(_dbk_dep ${_target_dep}_docbook)
    GET_FILENAME_COMPONENT( _source_base_name ${_dbk_source} NAME_WE )
    set( _output_chm ${_source_base_name}.chm )
    set( _output_hhp ${_source_base_name}.hhp )
    set( _output_toc_hhc ${_source_base_name}-toc.hhc )
    set( _docbook_plain_title ${_source_base_name}-plain-title.xml )
    get_docbook_xml_depends(_dbk_xml_deps "${_dbk_source}")

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
        # Dumb down our title. HTML Help can render most of our content
        # correctly because we tell it to use the IE9 rendering engine in
        # custom_layer_chm.xsl. However, this doesn't apply to the window
        # title or TOC. Neither "’" nor "&#8217;" will render correctly,
        # so just add a _title argument and set it in CMakeLists.txt.
        COMMAND ${PERL_EXECUTABLE} -p
           -e "s|<title>Wireshark.*s Guide</title>|<title>${_title}</title>|"
           < ${_dbk_source}
           > ${_docbook_plain_title}
        COMMAND ${XSLTPROC_EXECUTABLE}
            --path "${_xsltproc_path}"
            --stringparam base.dir ${_basedir}/
            --stringparam htmlhelp.title ${_title}
            --stringparam htmlhelp.chm ${_output_chm}
            --stringparam htmlhelp.hhp ${_output_hhp}
            --stringparam htmlhelp.hhc ${_output_toc_hhc}
            ${_common_xsltproc_args}
            --stringparam admon.graphics.path ${_gfxdir}/
            --nonet custom_layer_chm.xsl
            ${_docbook_plain_title}
        DEPENDS
            ${_dbk_xml_deps}
            ${_dbk_dep}
            # AsciiDoc uses UTF-8 by default, which is unsupported by HTML
            # Help. We may want to render an ISO-8859-1 version, or get rid
            # of HTML Help.
            custom_layer_chm.xsl
    )
ENDMACRO(XML2HHP)
