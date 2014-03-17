#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(LYNX_EXECUTABLE
  NAMES
    lynx
    elinks
    links
    true
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

# Convert html to text
IF(LYNX_EXECUTABLE MATCHES lynx)
	# (See Bug # 1446 for note re 'force-html' below)
	set(HTML2TXT "lynx -dump -width=72 -nolist -stdin -force-html")
ELSEIF(LYNX_EXECUTABLE MATCHES elinks)
	set(HTML2TXT "elinks -dump -dump-width 72")
ELSEIF(LYNX_EXECUTABLE MATCHES links)
	set(HTML2TXT "links -dump -width 72")
ELSEIF(LYNX_EXECUTABLE MATCHES true)
	set(HTML2TXT "true")
ELSE()
	message(ERROR "Should never be reached - please report!")
ENDIF()
message(STATUS "html2text: ${HTML2TXT}")
