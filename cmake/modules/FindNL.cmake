#
# $Id$
#
# - Find netlink
# Find the native netlink includes and library
#
#  NL_INCLUDE_DIRS - where to find libnl.h, etc.
#  NL_LIBRARIES    - List of libraries when using libnl3.
#  NL_FOUND        - True if libnl found.

IF (NL_LIBRARIES AND NL_INCLUDE_DIRS )
  # in cache already
  SET(NL_FOUND TRUE)
ELSE (NL_LIBRARIES AND NL_INCLUDE_DIRS )

  SET( SEARCHPATHS
      /opt/local
      /sw
      /usr
      /usr/local
  )

  FIND_PATH( NL_INCLUDE_DIR
    PATH_SUFFIXES
      include/libnl3
    NAMES
      netlink/version.h netlink/netlink.h
    PATHS
      $(SEARCHPATHS)
  )

  FIND_LIBRARY( NL_LIBRARY
    NAMES
      nl-3 nl
    PATH_SUFFIXES
      lib64 lib
    PATHS
      $(SEARCHPATHS)
  )

  FIND_LIBRARY( NLGENL_LIBRARY
    NAMES
      nl-genl-3 nl-genl
    PATH_SUFFIXES
      lib64 lib
    PATHS
      $(SEARCHPATHS)
  )

  FIND_LIBRARY( NLROUTE_LIBRARY
    NAMES
      nl-route-3 nl-route
    PATH_SUFFIXES
      lib64 lib
    PATHS
      $(SEARCHPATHS)
  )

ENDIF(NL_LIBRARIES AND NL_INCLUDE_DIRS)

# handle the QUIETLY and REQUIRED arguments and set NL_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(NL DEFAULT_MSG NL_LIBRARY NL_INCLUDE_DIR)

IF(NL_FOUND)
  SET( NL_LIBRARIES ${NLGENL_LIBRARY} ${NLROUTE_LIBRARY} ${NL_LIBRARY} )
  SET( NL_INCLUDE_DIRS ${NL_INCLUDE_DIR})
# FIXME: Differentiate between libnl versions
  SET( HAVE_LIBNL3 1 )
ELSE()
  SET( NL_LIBRARIES )
  SET( NL_INCLUDE_DIRS )
ENDIF()

MARK_AS_ADVANCED( NL_LIBRARIES NL_INCLUDE_DIRS )

