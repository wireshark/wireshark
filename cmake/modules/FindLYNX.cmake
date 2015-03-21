#
# - Find unix commands from cygwin
# This module looks for lynx (used by asciidoc)
#

INCLUDE(FindCygwin)

FIND_PROGRAM(LYNX_EXECUTABLE
  NAMES
    lynx
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LYNX DEFAULT_MSG LYNX_EXECUTABLE)

MARK_AS_ADVANCED(LYNX_EXECUTABLE)
