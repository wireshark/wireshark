#
# Look for the Linux setcap command (capabilities)
#

find_program( SETCAP_EXECUTABLE
  NAMES
    setcap
  PATHS
    /bin
    /usr/bin
    /usr/local/bin
    /sbin
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( SETCAP DEFAULT_MSG SETCAP_EXECUTABLE )

mark_as_advanced( SETCAP_EXECUTABLE )

