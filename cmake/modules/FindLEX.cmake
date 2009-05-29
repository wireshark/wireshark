# - Find lex executable
#

INCLUDE(FindCygwin)

FIND_PROGRAM(LEX_EXECUTABLE
  NAMES 
  flex
  lex
  PATH
  ${CYGWIN_INSTALL_PATH}/bin
  /bin
  /usr/bin 
  /usr/local/bin
  /sbin
)
MARK_AS_ADVANCED(
  LEX_EXECUTABLE
)

# flex a .l file

# search flex
MACRO(FIND_LEX)
    IF(NOT LEX_EXECUTABLE)
        FIND_PROGRAM(LEX_EXECUTABLE flex)
        IF (NOT LEX_EXECUTABLE)
          MESSAGE(FATAL_ERROR "flex not found - aborting")
        ENDIF (NOT LEX_EXECUTABLE)
    ENDIF(NOT LEX_EXECUTABLE)
ENDMACRO(FIND_LEX)

MACRO(ADD_LEX_FILES _sources )
    FIND_LEX()

    FOREACH (_current_FILE ${ARGN})
      GET_FILENAME_COMPONENT(_in ${_current_FILE} ABSOLUTE)
      GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)

      SET(_outc ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c)
      SET(_outh ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.h)

      ADD_CUSTOM_COMMAND(
         OUTPUT ${_outc} ${_outh}
         COMMAND ${LEX_EXECUTABLE}
         ARGS
         -o${_outc}
         --header-file=${_outh}
         ${_in}
         DEPENDS ${_in}
      )

      SET(${_sources} ${${_sources}} ${_outc} ${_outh} )
   ENDFOREACH (_current_FILE)
ENDMACRO(ADD_LEX_FILES)

