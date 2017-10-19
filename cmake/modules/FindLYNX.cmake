#
# This module looks for an HTML to plain text converter which accepts
# a "-dump" argument.
#
# Lynx is preferred since it generates URL footnotes.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(LYNX_EXECUTABLE
  NAMES
    lynx w3m links
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
