#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(A2X_EXECUTABLE
  NAMES
    a2x
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

# Make sure we don't get language specific quotes
set( A2X_EXECUTABLE LC_ALL=C ${A2X_EXECUTABLE} )

# Handle the QUIETLY and REQUIRED arguments and set ASCIIDOC_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ASCIIDOC DEFAULT_MSG A2X_EXECUTABLE)

MARK_AS_ADVANCED(A2X_EXECUTABLE)

MACRO( ASCIIDOC2HTML _output _asciidocsource _conf_files )
    GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
    set( A2X_HTML_OPTS --stylesheet=ws.css )

    SET( A2X_HTML_OPTS --stylesheet=ws.css )

    SET( _conf_opts_list )
    FOREACH( _conf_file ${_conf_files} )
        SET( _conf_opts_list ${_conf_opts_list} --conf-file=${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} )
    ENDFOREACH()
    STRING( REPLACE ";" " " _conf_opts "${_conf_opts_list}" )

    SET( _conf_deps )
    FOREACH( _conf_file ${_conf_files} )
        SET( _conf_deps ${_conf_deps} ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} )
    ENDFOREACH()

    ADD_CUSTOM_COMMAND(
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT
            ${_output}
        COMMAND ${A2X_EXECUTABLE}
            --format=xhtml
            --destination-dir=${CMAKE_CURRENT_BINARY_DIR}
            --asciidoc-opts=${_conf_opts}
            --fop
            ${A2X_HTML_OPTS}
            ${_asciidocsource}
        # Replacing file with itself will fail
        # COMMAND mv
        #     ${CMAKE_CURRENT_BINARY_DIR}/${_source_base_name}.html
        #     ${CMAKE_CURRENT_BINARY_DIR}/${_output}
        DEPENDS
            ${_asciidocsources}
            ${_conf_deps}
            ${_otherdependencies}
    )
ENDMACRO()

MACRO( ASCIIDOC2TXT _output _asciidocsource _conf_files )
    GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
    if( LYNX_EXECUTABLE MATCHES lynx )
        set( A2X_TEXT_OPTS --lynx )
    else()
        set( A2X_TEXT_OPTS  )
    endif()

    SET( A2X_HTML_OPTS --stylesheet=ws.css )

    SET( _conf_opts_list )
    FOREACH( _conf_file ${_conf_files} )
        SET( _conf_opts_list ${_conf_opts_list} --conf-file=${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} )
    ENDFOREACH()
    STRING( REPLACE ";" " " _conf_opts "${_conf_opts_list}" )

    SET( _conf_deps )
    FOREACH( _conf_file ${_conf_files} )
        SET( _conf_deps ${_conf_deps} ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} )
    ENDFOREACH()

    ADD_CUSTOM_COMMAND(
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT
            ${_output}
        COMMAND TZ=UTC ${A2X_EXECUTABLE}
            --format=text
            --destination-dir=${CMAKE_CURRENT_BINARY_DIR}
            --asciidoc-opts=${_conf_opts}
            --fop
            ${A2X_TEXT_OPTS}
            --xsltproc-opts '--stringparam generate.toc "article nop"'
            ${_asciidocsource}
        COMMAND mv
            ${CMAKE_CURRENT_BINARY_DIR}/${_source_base_name}.text
            ${CMAKE_CURRENT_BINARY_DIR}/${_output}
        DEPENDS
            ${_asciidocsource}
            ${_conf_deps}
    )
ENDMACRO()

# news: release-notes.txt
#         cp release-notes.txt ../NEWS

MACRO( ASCIIDOC2PDF _output _asciidocsource _conf_files _paper )
    GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )

    SET( A2X_HTML_OPTS --stylesheet=ws.css )

    SET( _conf_opts_list )
    FOREACH( _conf_file ${_conf_files} )
        SET( _conf_opts_list ${_conf_opts_list} --conf-file=${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} )
    ENDFOREACH()
    STRING( REPLACE ";" " " _conf_opts "${_conf_opts_list}")

    SET( _conf_deps )
    FOREACH( _conf_file ${_conf_files} )
        SET( _conf_deps ${_conf_deps} ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} )
    ENDFOREACH()

    ADD_CUSTOM_COMMAND(
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT
            ${_output}
        COMMAND ${A2X_EXECUTABLE}
            --format=pdf
            --destination-dir=${CMAKE_CURRENT_BINARY_DIR}
            --asciidoc-opts=${_conf_opts}
            --fop
            ${A2X_HTML_OPTS}
            --xsltproc-opts "--stringparam paper.type ${_paper} --nonet"
            --xsl-file=custom_layer_pdf.xsl
            ${_asciidocsource}
        COMMAND mv
            ${CMAKE_CURRENT_BINARY_DIR}/${_source_base_name}.pdf
            ${CMAKE_CURRENT_BINARY_DIR}/${_output}
        DEPENDS
            ${_asciidocsources}
            ${_conf_deps}
            ${_otherdependencies}
    )
ENDMACRO()
