# - Find lex executable
#

INCLUDE(FindCygwin)

FIND_PROGRAM(LEX_EXECUTABLE
  NAMES 
  lex
  flex
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

---------
# flex a .ll file

# search flex
MACRO(FIND_FLEX)
    IF(NOT FLEX_EXECUTABLE)
        FIND_PROGRAM(FLEX_EXECUTABLE flex)
        IF (NOT FLEX_EXECUTABLE)
          MESSAGE(FATAL_ERROR "flex not found - aborting")
        ENDIF (NOT FLEX_EXECUTABLE)
    ENDIF(NOT FLEX_EXECUTABLE)
ENDMACRO(FIND_FLEX)

MACRO(ADD_FLEX_FILES _sources )
    FIND_FLEX()

    FOREACH (_current_FILE ${ARGN})
      GET_FILENAME_COMPONENT(_in ${_current_FILE} ABSOLUTE)
      GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)

      SET(_out ${CMAKE_CURRENT_BINARY_DIR}/flex_${_basename}.cpp)

      ADD_CUSTOM_COMMAND(
         OUTPUT ${_out}
         COMMAND ${FLEX_EXECUTABLE}
         ARGS
         -o${_out}
         ${_in}
         DEPENDS ${_in}
      )

      SET(${_sources} ${${_sources}} ${_out} )
   ENDFOREACH (_current_FILE)
ENDMACRO(ADD_FLEX_FILES)

