#
# $Id$
#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

INCLUDE(FindCygwin)

FIND_PROGRAM(POD2MAN_EXECUTABLE
	NAMES
		pod2man
	PATHS
		${CYGWIN_INSTALL_PATH}/bin
		/bin
		/usr/bin
		/usr/local/bin
		/sbin
)

MARK_AS_ADVANCED(POD2MAN_EXECUTABLE)

# search pod2man
MACRO(FIND_POD2MAN)
	IF(NOT POD2MAN_EXECUTABLE)
		FIND_PROGRAM(POD2MAN_EXECUTABLE pod2man)
		IF (NOT POD2MAN_EXECUTABLE)
			MESSAGE(FATAL_ERROR "pod2man not found - aborting")
		ENDIF (NOT POD2MAN_EXECUTABLE)
	ENDIF(NOT POD2MAN_EXECUTABLE)
ENDMACRO(FIND_POD2MAN)

FIND_PROGRAM(POD2HTML_EXECUTABLE
	NAMES
		pod2html
	PATHS
		${CYGWIN_INSTALL_PATH}/bin
		/bin
		/usr/bin
		/usr/local/bin
		/sbin
)

MARK_AS_ADVANCED(POD2HTML_EXECUTABLE)

# search pod2html
MACRO(FIND_POD2HTML)
	IF(NOT POD2HTML_EXECUTABLE)
		FIND_PROGRAM(POD2HTML_EXECUTABLE pod2html)
		IF (NOT POD2HTML_EXECUTABLE)
			MESSAGE(FATAL_ERROR "pod2html not found - aborting")
		ENDIF (NOT POD2HTML_EXECUTABLE)
	ENDIF(NOT POD2HTML_EXECUTABLE)
ENDMACRO(FIND_POD2HTML)

# run pod2man and pod2html
MACRO(pod2manhtml _sourcefile _manext)
	GET_FILENAME_COMPONENT(_basefile ${_sourcefile} NAME)
	set(_outman ${_basefile}.${_manext})
	set(_outhtml ${_basefile}.html)
	ADD_CUSTOM_COMMAND(
		OUTPUT
			${_outman}
			${_outhtml}
		COMMAND
			${POD2MAN_EXECUTABLE}
			--section=${_manext}
			--center="The Wireshark Network Analyzer"
			--release=${CPACK_PACKAGE_VERSION}
			${_sourcefile}.pod
			> ${_outman}
		COMMAND
			${POD2HTML_EXECUTABLE}
			--title="${_basefile} - The Wireshark Network Analyzer ${CPACK_PACKAGE_VERSION}"
			--css=${CMAKE_SOURCE_DIR}/docbook/ws.css
			--noindex
			${_sourcefile}.pod
			> ${_outhtml}
		DEPENDS
			${_sourcefile}.pod
			${CMAKE_SOURCE_DIR}/docbook/ws.css
			
	)
ENDMACRO(pod2manhtml)

