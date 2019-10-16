#
# - Find pod2man and pod2html.
#

find_program(POD2MAN_EXECUTABLE
	NAMES
		pod2man
		pod2man.bat
	PATHS
		/bin
		/usr/bin
		/usr/local/bin
		/sbin
)

find_program(POD2HTML_EXECUTABLE
	NAMES
		pod2html
		pod2html.bat
	PATHS
		/bin
		/usr/bin
		/usr/local/bin
		/sbin
)

# handle the QUIETLY and REQUIRED arguments and set POD2HTML_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(POD DEFAULT_MSG POD2MAN_EXECUTABLE POD2HTML_EXECUTABLE)

mark_as_advanced(
	POD2MAN_EXECUTABLE
	POD2HTML_EXECUTABLE
)

# run pod2man and pod2html
macro(pod2manhtml _sourcefile _manext)
	get_filename_component(_basefile ${_sourcefile} NAME)
	set(_outman ${_basefile}.${_manext})
	set(_outhtml ${_basefile}.html)

	add_custom_command(
		OUTPUT
			${_outman}
		COMMAND
			${PERL_EXECUTABLE} ${POD2MAN_EXECUTABLE}
			--section=${_manext}
			--center=\"The Wireshark Network Analyzer\"
			--release=${CPACK_PACKAGE_VERSION}
			${_sourcefile}.pod
			> ${_outman}
		DEPENDS
			${_sourcefile}.pod
	)

	add_custom_command(
		OUTPUT
			${_outhtml}
		COMMAND
			${PERL_EXECUTABLE} ${POD2HTML_EXECUTABLE}
			--title=\"${_basefile} - The Wireshark Network Analyzer ${CPACK_PACKAGE_VERSION}\"
			--css=ws.css
			--noindex
			${_sourcefile}.pod
			> ${_outhtml}
		DEPENDS
			${_sourcefile}.pod
			${CMAKE_SOURCE_DIR}/docbook/ws.css
	)
endmacro(pod2manhtml)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
