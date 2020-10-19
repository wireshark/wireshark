#
# - Find bison/yacc executable
#

INCLUDE(FindChocolatey)

FIND_PROGRAM(YACC_EXECUTABLE
  NAMES
    win_bison
    bison
    yacc
  PATHS
    ${CHOCOLATEY_BIN_PATH}
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(YACC DEFAULT_MSG YACC_EXECUTABLE)

MARK_AS_ADVANCED(YACC_EXECUTABLE)

# Specifying "%pure-parser" will fail with a deprecation warning in
# Bison 3.4 and later. Specifying "%define api.pure" doesn't work with
# Berkeley YACC and older versions of Bison (such as 2.3, which ships
# with macOS). If we're using Bison and it's new, configure our .y.in
# files with "%define api.pure", otherwise use "%pure-parser".
set(YACC_PURE_PARSER_DIRECTIVE "%pure-parser")
if(YACC_EXECUTABLE)
    execute_process(COMMAND ${YACC_EXECUTABLE} -V OUTPUT_VARIABLE _yacc_full_version)
    string(REGEX MATCH "[1-9]+\.[0-9]+" _yacc_major_minor ${_yacc_full_version})
    if (_yacc_full_version MATCHES "GNU Bison" AND _yacc_major_minor VERSION_GREATER "2.6")
        set(YACC_PURE_PARSER_DIRECTIVE "%define api.pure")
    endif()
endif()

MACRO(ADD_YACC_FILES _source _generated)
    FOREACH (_current_FILE ${ARGN})
      configure_file(${_current_FILE}.in ${_current_FILE})
      GET_FILENAME_COMPONENT(_in ${CMAKE_CURRENT_BINARY_DIR}/${_current_FILE} ABSOLUTE)
      GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)

      SET(_out ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c)

      ADD_CUSTOM_COMMAND(
         OUTPUT ${_out}
         COMMAND ${YACC_EXECUTABLE}
           -d
           -p ${_basename}
           -o${_out}
           ${_in}
         DEPENDS ${_in}
      )
      LIST(APPEND ${_source} ${_in})
      LIST(APPEND ${_generated} ${_out})
   ENDFOREACH (_current_FILE)
ENDMACRO(ADD_YACC_FILES)

