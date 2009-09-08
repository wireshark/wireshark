# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(SH_EXECUTABLE
  NAMES
    sh
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

MARK_AS_ADVANCED(SH_EXECUTABLE)

# search sh
MACRO(FIND_SH)
    IF(NOT SH_EXECUTABLE)
        FIND_PROGRAM(SH_EXECUTABLE sh)
        IF (NOT SH_EXECUTABLE)
          MESSAGE(FATAL_ERROR "sh not found - aborting")
        ENDIF (NOT SH_EXECUTABLE)
    ENDIF(NOT SH_EXECUTABLE)
ENDMACRO(FIND_SH)

