#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)
#INCLUDE(FindChocolatey)

# Chocolatey's C:\Chocolatey\bin\win_flex and -\win_bison are
# currently unusable without some manual adjustments to the
# win_flex and win_bison wrapper scripts. Calling the executables
# directly should work.

FIND_PROGRAM(YACC_EXECUTABLE
  NAMES
    bison
    win_bison
    yacc
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
FIND_PACKAGE_HANDLE_STANDARD_ARGS(YACC DEFAULT_MSG YACC_EXECUTABLE)

MARK_AS_ADVANCED(YACC_EXECUTABLE)

MACRO(ADD_YACC_FILES _sources )
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
      SET(${_sources} ${${_sources}} ${_out} )
   ENDFOREACH (_current_FILE)
ENDMACRO(ADD_YACC_FILES)

