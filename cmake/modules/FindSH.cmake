#
# - Find unix commands from cygwin
# This module looks for some usual Unix commands.
#

include( FindCygwin )

find_program( SH_EXECUTABLE
  NAMES
    bash
  PATHS
    ${CYGWIN_INSTALL_PATH}/bin
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( SH DEFAULT_MSG SH_EXECUTABLE )

# Ensure this is Cygwin bash
if( WIN32 )
  execute_process( COMMAND ${SH_EXECUTABLE} --version OUTPUT_VARIABLE SH_VERSION )
  string( FIND "${SH_VERSION}" "cygwin" SH_IS_CYGWIN )
  if( ${SH_IS_CYGWIN} LESS 0 )
      set( BAD_SH ${SH_EXECUTABLE} )
      unset( SH_EXECUTABLE CACHE )
      message( FATAL_ERROR "The bash executable (${BAD_SH}) isn't from Cygwin.  Check your path" )
  endif()
  set( SH_FLAGS1 -o )
  set( SH_FLAGS2 igncr )
endif()

mark_as_advanced( SH_EXECUTABLE )

