#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(YAPP_EXECUTABLE
  NAMES
    yapp
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(YAPP DEFAULT_MSG YAPP_EXECUTABLE)

MARK_AS_ADVANCED(YAPP_EXECUTABLE)

