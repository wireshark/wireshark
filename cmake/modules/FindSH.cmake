#
# $Id$
#
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

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(SH DEFAULT_MSG SH_EXECUTABLE)

MARK_AS_ADVANCED(SH_EXECUTABLE)

