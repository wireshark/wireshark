#
# - Find Doxygen
# This module looks for a native (non-Cygwin) Doxygen.
#

find_program( DOXYGEN_EXECUTABLE
  NAMES
    doxygen
  PATHS
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

# We set various paths in doxygen.cfg via configure_file(). These are
# native system paths which aren't compatible with Cygwin's Doxygen.
string(TOLOWER ${DOXYGEN_EXECUTABLE} _de_lower)
if(${_de_lower} MATCHES "cyg")
	set(_ignore_reason "Cygwin Doxygen found at ${DOXYGEN_EXECUTABLE}. Ignoring.")
	message(STATUS ${_ignore_reason})
	set(DOXYGEN_EXECUTABLE DOXYGEN_EXECUTABLE-NOTFOUND CACHE FILEPATH ${_ignore_reason} FORCE)
endif()

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

