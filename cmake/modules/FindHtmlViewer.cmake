#
# $Id$
#
# - Find an html viewer program
#
#  HTML_VIEWER_EXECUTABLE - the full path to perl
#  HTML_VIEWER_FOUND      - If false, don't attempt to use perl.

INCLUDE(FindCygwin)

FIND_PROGRAM(HTML_VIEWER_EXECUTABLE
  NAMES
    xdg-open
    mozilla
    htmlview
    ENV{HTML_VIEWER}
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(HtmlViewer DEFAULT_MSG HTML_VIEWER_EXECUTABLE)

# For compat with configure
SET(HTML_VIEWER ${HTML_VIEWER_EXECUTABLE})


MARK_AS_ADVANCED(HTML_VIEWER_EXECUTABLE)
