# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(YACC_EXECUTABLE
  NAMES
    bison
    yacc
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

MARK_AS_ADVANCED(YACC_EXECUTABLE)

# search bison/yacc
MACRO(FIND_YACC)
    IF(NOT YACC_EXECUTABLE)
        FIND_PROGRAM(YACC_EXECUTABLE bison)
        IF (NOT YACC_EXECUTABLE)
          MESSAGE(FATAL_ERROR "bison/yacc not found - aborting")
        ENDIF (NOT YACC_EXECUTABLE)
    ENDIF(NOT YACC_EXECUTABLE)
ENDMACRO(FIND_YACC)

MACRO(ADD_YACC_FILES _sources )
    FIND_YACC()

    FOREACH (_current_FILE ${ARGN})
      GET_FILENAME_COMPONENT(_in ${_current_FILE} ABSOLUTE)
      GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)

      SET(_out ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c)

      ADD_CUSTOM_COMMAND(
         OUTPUT ${_out}
         COMMAND ${YACC_EXECUTABLE}
         ARGS
         -d
         -p ${_basename}
         -o${_out}
         ${_in}
         DEPENDS ${_in}
      )

      SET(${_sources} ${${_sources}} ${_out} )
   ENDFOREACH (_current_FILE)
ENDMACRO(ADD_YACC_FILES)

