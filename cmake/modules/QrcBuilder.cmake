# QrcBuilder.cmake
#
# Generic helper to build Qt .qrc files at configure time.
#
# Usage:
#   qrc_register(NAME my_resources PREFIX "/stylesheets")
#   qrc_add_file(NAME my_resources FILE "/abs/path/foo.qss" ALIAS "foo.qss")
#   qrc_add_files(NAME my_resources
#                 FILES a.qss b.qss
#                 BASE_DIR "${CMAKE_SOURCE_DIR}/ui/stylesheets")
#   qrc_add_glob(NAME my_resources
#                GLOB "${CMAKE_SOURCE_DIR}/resources/banners/*"
#                ALIAS_PREFIX "banners/")
#   qrc_finalize(NAME my_resources OUTPUT_VAR my_qrc_path)
#
# The generated .qrc file lives in ${CMAKE_CURRENT_BINARY_DIR}/<name>.qrc
# and its path is returned via OUTPUT_VAR so it can be appended to the
# list of qrc files passed to qt_add_resources / add_executable.
#
# SPDX-License-Identifier: GPL-2.0-or-later

include_guard(GLOBAL)

# -- Internal helpers ---------------------------------------------------------

# Internal: build the property key for a (scope, name) pair.
function(_qrc_key _scope _name _suffix _out_var)
    set(${_out_var} "_qrc_${_scope}__${_name}_${_suffix}" PARENT_SCOPE)
endfunction()

function(_qrc_resolve_scope _arg_scope _out_var)
    if(_arg_scope)
        set(${_out_var} "${_arg_scope}" PARENT_SCOPE)
    elseif(PROJECT_NAME)
        set(${_out_var} "${PROJECT_NAME}" PARENT_SCOPE)
    else()
        message(FATAL_ERROR
            "QrcBuilder: no TARGET/SCOPE given and PROJECT_NAME is unset. "
            "Either pass TARGET <name> or call project() first.")
    endif()
endfunction()

function(_qrc_require_registered _scope _name)
    _qrc_key("${_scope}" "${_name}" "registered" _key)
    get_property(_registered GLOBAL PROPERTY "${_key}")
    if(NOT _registered)
        message(FATAL_ERROR
            "QrcBuilder: resource '${_name}' is not registered in scope "
            "'${_scope}'. Call qrc_register(NAME ${_name} TARGET ${_scope} ...) first.")
    endif()
endfunction()

function(_qrc_append_entry _scope _name _alias _path _compress _generated)
    if(NOT EXISTS "${_path}" AND NOT _generated)
        message(FATAL_ERROR
            "QrcBuilder: File does not exist: ${_path}\n"
            "  Resource: ${_name} (scope: ${_scope})\n"
            "  Alias: ${_alias}\n"
            "Check the file path and ensure the file exists before adding to QRC.")
    endif()

    # Build the file entry with optional compression
    if(_compress)
        set(_file_entry "        <file alias=\"${_alias}\" compress-algo=\"${_compress}\">${_path}</file>\n")
    else()
        set(_file_entry "        <file alias=\"${_alias}\">${_path}</file>\n")
    endif()

    _qrc_key("${_scope}" "${_name}" "entries" _key)
    set_property(GLOBAL APPEND PROPERTY "${_key}" "${_file_entry}")
endfunction()

function(qrc_debug_dump)
    cmake_parse_arguments(ARG "" "TARGET" "" ${ARGN})
    if(ARG_TARGET)
        set(_scope "${ARG_TARGET}")
    elseif(PROJECT_NAME)
        set(_scope "${PROJECT_NAME}")
    else()
        message(STATUS "QrcBuilder debug: no scope to dump")
        return()
    endif()

    message(STATUS "=== QrcBuilder state for scope '${_scope}' ===")

    # Get all global properties and filter for our pattern
    get_cmake_property(_all_props GLOBAL_PROPERTIES)
    foreach(_prop ${_all_props})
        if(_prop MATCHES "^_qrc_${_scope}__(.+)_(.+)$")
            set(_name "${CMAKE_MATCH_1}")
            set(_suffix "${CMAKE_MATCH_2}")
            get_property(_value GLOBAL PROPERTY "${_prop}")
            message(STATUS "  ${_name}.${_suffix}: ${_value}")
        endif()
    endforeach()
endfunction()

# -- Public API ---------------------------------------------------------------

function(qrc_register)
    cmake_parse_arguments(ARG "" "NAME;PREFIX;TARGET" "" ${ARGN})
    if(NOT ARG_NAME OR NOT ARG_PREFIX)
        message(FATAL_ERROR "qrc_register: NAME and PREFIX are required")
    endif()
    _qrc_resolve_scope("${ARG_TARGET}" _scope)

    _qrc_key("${_scope}" "${ARG_NAME}" "registered" _key_reg)
    get_property(_already GLOBAL PROPERTY "${_key_reg}")
    if(_already)
        message(FATAL_ERROR
            "qrc_register: '${ARG_NAME}' already registered in scope '${_scope}'")
    endif()

    _qrc_key("${_scope}" "${ARG_NAME}" "prefix"  _key_prefix)
    _qrc_key("${_scope}" "${ARG_NAME}" "entries" _key_entries)
    set_property(GLOBAL PROPERTY "${_key_reg}"     TRUE)
    set_property(GLOBAL PROPERTY "${_key_prefix}"  "${ARG_PREFIX}")
    set_property(GLOBAL PROPERTY "${_key_entries}" "")
endfunction()

function(qrc_add_file)
    cmake_parse_arguments(ARG "" "NAME;FILE;ALIAS;TARGET;COMPRESS;GENERATED" "" ${ARGN})
    if(NOT ARG_NAME OR NOT ARG_FILE OR NOT ARG_ALIAS)
        message(FATAL_ERROR "qrc_add_file: NAME, FILE and ALIAS are required")
    endif()
    _qrc_resolve_scope("${ARG_TARGET}" _scope)
    _qrc_require_registered("${_scope}" "${ARG_NAME}")
    _qrc_append_entry("${_scope}" "${ARG_NAME}" "${ARG_ALIAS}" "${ARG_FILE}" "${ARG_COMPRESS}" "${ARG_GENERATED}")
endfunction()

function(qrc_add_files)
    cmake_parse_arguments(ARG "" "NAME;BASE_DIR;ALIAS_PREFIX;TARGET;COMPRESS;GENERATED" "FILES" ${ARGN})
    if(NOT ARG_NAME OR NOT ARG_FILES)
        message(FATAL_ERROR "qrc_add_files: NAME and FILES are required")
    endif()
    _qrc_resolve_scope("${ARG_TARGET}" _scope)
    _qrc_require_registered("${_scope}" "${ARG_NAME}")

    foreach(_file ${ARG_FILES})
        if(ARG_BASE_DIR)
            file(RELATIVE_PATH _alias "${ARG_BASE_DIR}" "${_file}")
        else()
            get_filename_component(_alias "${_file}" NAME)
        endif()
        if(ARG_ALIAS_PREFIX)
            set(_alias "${ARG_ALIAS_PREFIX}${_alias}")
        endif()
        _qrc_append_entry("${_scope}" "${ARG_NAME}" "${_alias}" "${_file}" "${ARG_COMPRESS}" "${ARG_GENERATED}")
    endforeach()
endfunction()

function(qrc_add_glob)
    cmake_parse_arguments(ARG "" "NAME;GLOB;BASE_DIR;ALIAS_PREFIX;TARGET;COMPRESS;GENERATED" "" ${ARGN})
    if(NOT ARG_NAME OR NOT ARG_GLOB)
        message(FATAL_ERROR "qrc_add_glob: NAME and GLOB are required")
    endif()
    _qrc_resolve_scope("${ARG_TARGET}" _scope)
    _qrc_require_registered("${_scope}" "${ARG_NAME}")

    file(GLOB _matched LIST_DIRECTORIES false "${ARG_GLOB}")
    qrc_add_files(
        TARGET       "${_scope}"
        NAME         "${ARG_NAME}"
        FILES        ${_matched}
        BASE_DIR     "${ARG_BASE_DIR}"
        ALIAS_PREFIX "${ARG_ALIAS_PREFIX}"
        COMPRESS     "${ARG_COMPRESS}"
        GENERATED    "${ARG_GENERATED}"
    )
endfunction()

function(qrc_finalize)
    cmake_parse_arguments(ARG "" "NAME;OUTPUT_VAR;OUTPUT_DIR;TARGET;OUTPUT_FILE_NAME" "" ${ARGN})
    if(NOT ARG_NAME OR NOT ARG_OUTPUT_VAR)
        message(FATAL_ERROR "qrc_finalize: NAME and OUTPUT_VAR are required")
    endif()
    _qrc_resolve_scope("${ARG_TARGET}" _scope)
    _qrc_require_registered("${_scope}" "${ARG_NAME}")

    if(NOT ARG_OUTPUT_DIR)
        set(ARG_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
    endif()

    _qrc_key("${_scope}" "${ARG_NAME}" "prefix"  _key_prefix)
    _qrc_key("${_scope}" "${ARG_NAME}" "entries" _key_entries)
    get_property(_prefix  GLOBAL PROPERTY "${_key_prefix}")
    get_property(_entries GLOBAL PROPERTY "${_key_entries}")

    string(REPLACE ";" "" _entries_joined "${_entries}")

    set(_header
"<!--
    AUTO-GENERATED FILE — DO NOT EDIT.
    Generated by QrcBuilder.cmake during CMake configuration.
    Scope         : ${_scope}
    Resource name : ${ARG_NAME}
    Prefix        : ${_prefix}
    Source        : ${CMAKE_CURRENT_LIST_FILE}
    Any manual changes will be overwritten on the next CMake run.
-->
")

    # Scope the output filename too, so two targets writing into the same
    # binary dir don't overwrite each other. Allow for an override if desired.
    set(_output_file_name "${_scope}_${ARG_NAME}.qrc")
    if(ARG_OUTPUT_FILE_NAME)
	set(_output_file_name "${ARG_OUTPUT_FILE_NAME}")
    endif()
    set(_qrc_path "${ARG_OUTPUT_DIR}/${_output_file_name}")
    file(WRITE "${_qrc_path}"
        "${_header}<RCC>\n    <qresource prefix=\"${_prefix}\">\n${_entries_joined}    </qresource>\n</RCC>\n")

    set(${ARG_OUTPUT_VAR} "${_qrc_path}" PARENT_SCOPE)
endfunction()
