#
# - Find flex/lex executable
#

include(FindChocolatey)

find_program(LEX_EXECUTABLE
  NAMES
    win_flex
    flex
    lex
  PATHS
    ${CHOCOLATEY_BIN_PATH}
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LEX DEFAULT_MSG LEX_EXECUTABLE)

MARK_AS_ADVANCED(LEX_EXECUTABLE)

# flex a .l file

MACRO(ADD_LEX_FILES _source _generated)
    FOREACH (_current_FILE ${ARGN})
      GET_FILENAME_COMPONENT(_in ${_current_FILE} ABSOLUTE)
      GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)

      SET(_outc ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c)
      SET(_outh ${CMAKE_CURRENT_BINARY_DIR}/${_basename}_lex.h)

      ADD_CUSTOM_COMMAND(
        OUTPUT ${_outc} ${_outh}
        COMMAND ${LEX_EXECUTABLE} -o${_outc} --header-file=${_outh} ${_in}
        DEPENDS ${_in}
      )
      LIST(APPEND ${_source} ${_in})
      LIST(APPEND ${_generated} ${_outc})
      INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
      INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})
    ENDFOREACH (_current_FILE)
ENDMACRO(ADD_LEX_FILES)

