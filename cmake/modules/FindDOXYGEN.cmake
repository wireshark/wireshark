#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

include( FindCygwin )

find_program( DOXYGEN_EXECUTABLE
  NAMES
    doxygen
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( DOXYGEN DEFAULT_MSG DOXYGEN_EXECUTABLE )

mark_as_advanced( DOXYGEN_EXECUTABLE )

macro( DOXYGEN2HTML _output )
	GET_FILENAME_COMPONENT(_OUTDIR ${_output} PATH)
	SET(_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/${_OUTDIR})

	add_custom_command(
		OUTPUT
		COMMAND cmake
			-E make_directory ${_OUTDIR}
		COMMAND $(DOXYGEN_EXECUTABLE)
			doxygen.cfg
		COMMAND chmod
			-R og+rX ${_OUTDIR}
		DEPENDS
			doxygen.cfg
	)
endmacro()

