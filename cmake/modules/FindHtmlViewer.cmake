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
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

IF (NOT HTML_VIEWER_EXECUTABLE)
  MESSAGE(FATAL_ERROR "HTML_VIEWER not found - aborting")
ELSE ()
  SET (HTML_VIEWER_FOUND "YES")
  MESSAGE(STATUS "Found HTML_VIEWER: ${HTML_VIEWER_EXECUTABLE}")
ENDIF ()


# For compat with configure
SET(HTML_VIEWER ${HTML_VIEWER_EXECUTABLE})


MARK_AS_ADVANCED(HTML_VIEWER_EXECUTABLE)
