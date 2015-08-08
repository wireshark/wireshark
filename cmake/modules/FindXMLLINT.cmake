#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(XMLLINT_EXECUTABLE
    NAMES
        xmllint
    PATHS
        ${CYGWIN_INSTALL_PATH}/bin
        /bin
        /usr/bin
        /usr/local/bin
        /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(XMLLINT DEFAULT_MSG XMLLINT_EXECUTABLE)

MARK_AS_ADVANCED(XMLLINT_EXECUTABLE)

if (WIN32 AND NOT "${CYGWIN_INSTALL_PATH}" STREQUAL "" AND ${XMLLINT_EXECUTABLE} MATCHES "${CYGWIN_INSTALL_PATH}")
    FIND_PROGRAM(CYGPATH_EXECUTABLE
        NAMES cygpath
        PATHS ${CYGWIN_INSTALL_PATH}/bin
    )
    # XXX Duplicate of TO_A2X_COMPATIBLE_PATH
    MACRO( TO_XMLLINT_COMPATIBLE_PATH _cmake_path _result )
        execute_process(
            COMMAND ${CYGPATH_EXECUTABLE} -u ${_cmake_path}
            OUTPUT_VARIABLE _cygwin_path
        )
        # cygpath adds a linefeed.
        string(STRIP "${_cygwin_path}" _cygwin_path)

        set( ${_result} ${_cygwin_path} )
    ENDMACRO()

    TO_XMLLINT_COMPATIBLE_PATH( ${CMAKE_CURRENT_SOURCE_DIR} _xmllint_current_source_dir )
    TO_XMLLINT_COMPATIBLE_PATH( ${CMAKE_CURRENT_BINARY_DIR} _xmllint_current_binary_dir )

    set ( _xmllint_path "${_xmllint_current_source_dir}:${_xmllint_current_binary_dir}:${_xmllint_current_binary_dir}/wsluarm_src")
else()
    set ( _xmllint_path "${CMAKE_CURRENT_SOURCE_DIR}:${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/wsluarm_src")
endif()

# Validate XML
# XXX Unused?
MACRO(VALIDATE_XML _validated _sources)
    # FIXME: How do I extract the first element of a variable containing a
    # list of values? Isn't there a "cleaner" solution?
    # Oh, and I have no idea why I can't directly use _source instead of
    # having to introduce _tmpsource.
    FOREACH(_tmpsource ${${_sources}})
        set(_source ${_tmpsource})
        BREAK()
    ENDFOREACH()
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${_validated}
        COMMAND ${XMLLINT_EXECUTABLE}
            --path "${_xmllint_path}"
            --valid
            --noout
            ${_source}
        COMMAND ${CMAKE_COMMAND} -E touch
            ${_validated}
        DEPENDS
            ${${_sources}}
    )
ENDMACRO(VALIDATE_XML)
