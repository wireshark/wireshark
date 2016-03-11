#
# - Find bison/yacc executable
#

INCLUDE(FindCygwin)
INCLUDE(FindChocolatey)

FIND_PROGRAM(YACC_EXECUTABLE
  NAMES
    bison
    win_bison
    yacc
  PATHS
    ${CHOCOLATEY_BIN_PATH}/bin
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(YACC DEFAULT_MSG YACC_EXECUTABLE)

MARK_AS_ADVANCED(YACC_EXECUTABLE)

MACRO(ADD_YACC_FILES _source _generated)
    FOREACH (_current_FILE ${ARGN})
      GET_FILENAME_COMPONENT(_in ${_current_FILE} ABSOLUTE)
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

