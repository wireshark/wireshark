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

# FIXME: Don't match on the name but check whether the argument is
#   accepted or not. OTOH, if it isn't accepted, build will fail on Win.
if( WIN32 )
  set( SH_FLAGS1 -o )
  set( SH_FLAGS2 igncr )
endif()

mark_as_advanced( SH_EXECUTABLE )

