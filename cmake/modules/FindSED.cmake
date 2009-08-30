# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(SED_EXECUTABLE
  NAMES
    sed
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

MARK_AS_ADVANCED(SED_EXECUTABLE)

# search sed
MACRO(FIND_SED)
    IF(NOT SED_EXECUTABLE)
        FIND_PROGRAM(SED_EXECUTABLE sed)
        IF (NOT SED_EXECUTABLE)
          MESSAGE(FATAL_ERROR "sed not found - aborting")
        ENDIF (NOT SED_EXECUTABLE)
    ENDIF(NOT SED_EXECUTABLE)
ENDMACRO(FIND_SED)

