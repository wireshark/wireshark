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

# handle the QUIETLY and REQUIRED arguments and set POD2HTML_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(POD DEFAULT_MSG POD2MAN_EXECUTABLE POD2HTML_EXECUTABLE)

MARK_AS_ADVANCED(
	POD2MAN_EXECUTABLE
	POD2HTML_EXECUTABLE
)

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
			${PERL_EXECUTABLE} ${POD2MAN_EXECUTABLE}
			--section=${_manext}
			--center="The Wireshark Network Analyzer"
			--release=${CPACK_PACKAGE_VERSION}
			${_sourcefile}.pod
			> ${_outman}
		COMMAND
			${PERL_EXECUTABLE} ${POD2HTML_EXECUTABLE}
			--title="${_basefile} - The Wireshark Network Analyzer ${CPACK_PACKAGE_VERSION}"
			--css=ws.css
			--noindex
			${_sourcefile}.pod
			> ${_outhtml}
		DEPENDS
			${_sourcefile}.pod
			${CMAKE_SOURCE_DIR}/docbook/ws.css
	)
ENDMACRO(pod2manhtml)

