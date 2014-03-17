#
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

# handle the QUIETLY and REQUIRED arguments and set SED_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(SED DEFAULT_MSG SED_EXECUTABLE)

MARK_AS_ADVANCED(SED_EXECUTABLE)

