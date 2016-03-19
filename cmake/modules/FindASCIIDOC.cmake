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

string( TOLOWER "${CYGWIN_INSTALL_PATH}" l_cyg_path)
string( TOLOWER "${A2X_EXECUTABLE}" l_a2x_ex)
if (NOT "${CYGWIN_INSTALL_PATH}" STREQUAL "" AND "${l_a2x_ex}" MATCHES "${l_cyg_path}")
    message(STATUS "Using Cygwin a2x")
    # We have most likely found a symlink to a2x.py. This won't work from the Windows shell.
    FIND_PROGRAM(CYGPATH_EXECUTABLE
        NAMES cygpath
        PATHS ${CYGWIN_INSTALL_PATH}/bin
    )

    MACRO( TO_A2X_COMPATIBLE_PATH _cmake_path _result )
        execute_process(
            COMMAND ${CYGPATH_EXECUTABLE} -u ${_cmake_path}
            OUTPUT_VARIABLE _cygwin_path
        )
        # cygpath adds a linefeed.
        string(STRIP "${_cygwin_path}" _cygwin_path)

        set( ${_result} ${_cygwin_path} )
    ENDMACRO()

    TO_A2X_COMPATIBLE_PATH( ${CMAKE_SOURCE_DIR}/tools/runa2x.sh RUNA2X_CYGWIN_PATH )

    # It's difficult or impossible to call /usr/bin/a2x directly from
    # Windows because:
    # - /usr/bin/a2x, which is a symlink to /usr/bin/a2x.py.
    # - We need to set environment variables (LC_ALL, PATH, TZ, PYTHONHOME)
    # so we use a wrapper script.
    set( RUNA2X ${SH_EXECUTABLE} ${RUNA2X_CYGWIN_PATH} )
else()
    # Make sure we don't get language specific quotes
    set( RUNA2X LC_ALL=C TZ=UTC ${A2X_EXECUTABLE} )

    MACRO( TO_A2X_COMPATIBLE_PATH _cmake_path _result )
        set( ${_result} ${_cmake_path} )
    ENDMACRO()
endif()

# Handle the QUIETLY and REQUIRED arguments and set ASCIIDOC_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ASCIIDOC DEFAULT_MSG RUNA2X)

MARK_AS_ADVANCED(RUNA2X)

TO_A2X_COMPATIBLE_PATH( ${CMAKE_CURRENT_BINARY_DIR} _a2x_current_binary_dir )

MACRO( ASCIIDOC2DOCBOOK _asciidocsource _conf_files _src_files _built_deps )
    GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
    set( A2X_HTML_OPTS --stylesheet=ws.css )
    set( _output_xml ${_source_base_name}.xml )
    set( _output_dbk ${_source_base_name}.dbk )

    foreach(_conf_file ${${_conf_files}})
        TO_A2X_COMPATIBLE_PATH ( ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} _a2x_conf_file )
        set( _conf_opts_list ${_conf_opts_list} --conf-file=${_a2x_conf_file})
    endforeach()
    string( REPLACE ";" " " _conf_opts "${_conf_opts_list}")

    foreach(_conf_file ${${_conf_files}})
        set( _conf_deps ${_conf_deps} ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file})
    endforeach()

    foreach(_src_file ${${_src_files}})
        set( _src_deps ${_src_deps} ${CMAKE_CURRENT_SOURCE_DIR}/${_src_file})
    endforeach()

    TO_A2X_COMPATIBLE_PATH ( ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource} _a2x_asciidocsource )

    add_custom_command(
        OUTPUT
            ${_output_xml}
        # XXX - Output to a specific directory, e.g. wsdg_generated_src
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND ${RUNA2X}
            --verbose
            --attribute=build_dir=${_a2x_current_binary_dir}
            --attribute=docinfo
            --destination-dir=${_a2x_current_binary_dir}
            --asciidoc-opts=${_conf_opts}
            --no-xmllint
            --format=docbook
            --fop
            ${A2X_HTML_OPTS}
            ${_a2x_asciidocsource}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
            ${_conf_deps}
            ${_src_deps}
            ${${_built_deps}}
    )
    add_custom_target(generate_${_output_xml} DEPENDS ${_output_xml})
    set_target_properties(generate_${_output_xml} PROPERTIES FOLDER "Docbook")
    unset(_src_deps)
    unset(_conf_deps)
    unset(_conf_opts_list)
ENDMACRO()

MACRO( ASCIIDOC2HTML _output _asciidocsource _conf_files )
    GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
    set( A2X_HTML_OPTS --stylesheet=ws.css )

    SET( A2X_HTML_OPTS --stylesheet=ws.css )

    SET( _conf_opts_list )
    FOREACH( _conf_file ${_conf_files} )
        TO_A2X_COMPATIBLE_PATH ( ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} _a2x_conf_file )
        SET( _conf_opts_list ${_conf_opts_list} --conf-file=${_a2x_conf_file})
    ENDFOREACH()
    STRING( REPLACE ";" " " _conf_opts "${_conf_opts_list}" )

    SET( _conf_deps )
    FOREACH( _conf_file ${_conf_files} )
        SET( _conf_deps ${_conf_deps} ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} )
    ENDFOREACH()

    TO_A2X_COMPATIBLE_PATH ( ${_asciidocsource} _a2x_asciidocsource )

    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND ${RUNA2X}
            --format=xhtml
            --destination-dir=${_a2x_current_binary_dir}
            --asciidoc-opts=${_conf_opts}
            --fop
            ${A2X_HTML_OPTS}
            ${_a2x_asciidocsource}
        # Replacing file with itself will fail
        # COMMAND ${CMAKE_COMMAND} -E rename
        #     ${CMAKE_CURRENT_BINARY_DIR}/${_source_base_name}.html
        #     ${CMAKE_CURRENT_BINARY_DIR}/${_output}
        DEPENDS
            ${_asciidocsources}
            ${_conf_deps}
            ${_otherdependencies}
    )
    unset(_conf_deps)
    unset(_conf_opts_list)
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
        TO_A2X_COMPATIBLE_PATH ( ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} _a2x_conf_file )
        SET( _conf_opts_list ${_conf_opts_list} --conf-file=${_a2x_conf_file})
    ENDFOREACH()
    STRING( REPLACE ";" " " _conf_opts "${_conf_opts_list}" )

    SET( _conf_deps )
    FOREACH( _conf_file ${_conf_files} )
        SET( _conf_deps ${_conf_deps} ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} )
    ENDFOREACH()

    TO_A2X_COMPATIBLE_PATH ( ${_asciidocsource} _a2x_asciidocsource )

    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND ${RUNA2X}
            --format=text
            --destination-dir=${_a2x_current_binary_dir}
            --asciidoc-opts=${_conf_opts}
            --fop
            ${A2X_TEXT_OPTS}
            # XXX This generates a CMake working but correcting it looks
            # messy.
            --xsltproc-opts '--stringparam generate.toc "article nop" '
            ${_a2x_asciidocsource}
        COMMAND ${CMAKE_COMMAND} -E rename
            ${CMAKE_CURRENT_BINARY_DIR}/${_source_base_name}.text
            ${CMAKE_CURRENT_BINARY_DIR}/${_output}
        DEPENDS
            ${_asciidocsource}
            ${_conf_deps}
    )
    unset(_conf_deps)
    unset(_conf_opts_list)
ENDMACRO()

# news: release-notes.txt
#         ${CMAKE_COMMAND} -E copy_if_different release-notes.txt ../NEWS

MACRO( ASCIIDOC2PDF _output _asciidocsource _conf_files _paper )
    GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )

    SET( A2X_HTML_OPTS --stylesheet=ws.css )

    SET( _conf_opts_list )
    FOREACH( _conf_file ${_conf_files} )
        TO_A2X_COMPATIBLE_PATH ( ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} _a2x_conf_file )
        SET( _conf_opts_list ${_conf_opts_list} --conf-file=${_a2x_conf_file})
    ENDFOREACH()
    STRING( REPLACE ";" " " _conf_opts "${_conf_opts_list}")

    SET( _conf_deps )
    FOREACH( _conf_file ${_conf_files} )
        SET( _conf_deps ${_conf_deps} ${CMAKE_CURRENT_SOURCE_DIR}/${_conf_file} )
    ENDFOREACH()

    TO_A2X_COMPATIBLE_PATH ( ${_asciidocsource} _a2x_asciidocsource )

    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_output}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND ${RUNA2X}
            --format=pdf
            --destination-dir=${_a2x_current_binary_dir}
            --asciidoc-opts=${_conf_opts}
            --fop
            ${A2X_HTML_OPTS}
            --xsltproc-opts "--stringparam paper.type ${_paper} --nonet"
            --xsl-file=custom_layer_pdf.xsl
            ${_a2x_asciidocsource}
        COMMAND ${CMAKE_COMMAND} -E rename
            ${CMAKE_CURRENT_BINARY_DIR}/${_source_base_name}.pdf
            ${CMAKE_CURRENT_BINARY_DIR}/${_output}
        DEPENDS
            ${_asciidocsources}
            ${_conf_deps}
            ${_otherdependencies}
    )
    unset(_conf_deps)
    unset(_conf_opts_list)
ENDMACRO()
