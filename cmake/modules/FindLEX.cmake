#
# - Find lex executable
#

INCLUDE(FindCygwin)
#INCLUDE(FindChocolatey)

# Chocolatey's C:\Chocolatey\bin\win_flex and -\win_bison are
# currently unusable without some manual adjustments to the
# win_flex and win_bison wrapper scripts. Calling the executables
# directly should work.

FIND_PROGRAM(LEX_EXECUTABLE
  NAMES
    flex
    win_flex
    lex
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
#    ${CHOCOLATEY_INSTALL_PATH}/bin
#    ${CHOCOLATEY_INSTALL_PATH}/lib/winflexbison.2.4.1.20140103/tools
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LEX DEFAULT_MSG LEX_EXECUTABLE)

MARK_AS_ADVANCED(LEX_EXECUTABLE)

# flex a .l file

MACRO(ADD_LEX_FILES _sources )
    FOREACH (_current_FILE ${ARGN})
      GET_FILENAME_COMPONENT(_in ${_current_FILE} ABSOLUTE)
      GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)

      SET(_outc ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.c)
      SET(_outh ${CMAKE_CURRENT_BINARY_DIR}/${_basename}_lex.h)

      ADD_CUSTOM_COMMAND(
        OUTPUT ${_outc}
        COMMAND ${SH_EXECUTABLE} ${SH_FLAGS1} ${SH_FLAGS2} ${CMAKE_SOURCE_DIR}/tools/runlex.sh ${LEX_EXECUTABLE} ${SED_EXECUTABLE}
          -o${_outc}
          --header-file=${_outh}
          ${_in}
        DEPENDS ${_in}
      )
    SET(${_sources} ${${_sources}} ${_outc} )
    INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
  ENDFOREACH (_current_FILE)
ENDMACRO(ADD_LEX_FILES)

