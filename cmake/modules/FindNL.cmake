#
# Find the native netlink includes and library
#
# Only look for version 3 (>= 3.2), which started appending the major version
# number as suffix to library names (libnl-3). Version 2 was short-lived,
# and version 1 has API and ABI incompatibilities.
#
#  NL_INCLUDE_DIRS - where to find libnl.h, etc.
#  NL_LIBRARIES    - List of libraries when using libnl.
#  NL_FOUND        - True if libnl found.

if(NL_LIBRARIES AND NL_INCLUDE_DIRS)
  # in cache already
  SET(NL_FOUND TRUE)
else()
  SET( SEARCHPATHS
      /opt/local
      /sw
      /usr
      /usr/local
  )

  find_package(PkgConfig)
  pkg_check_modules(NL3 libnl-3.0 libnl-genl-3.0 libnl-route-3.0)

  # Try to find NL >= 3.2 (/usr/include/libnl3/netlink/version.h)
  find_path(NL3_INCLUDE_DIR
    PATH_SUFFIXES
      include/libnl3
      include
    NAMES
      netlink/version.h
    HINTS
      "${NL3_libnl-3.0_INCLUDEDIR}"
    PATHS
      $(SEARCHPATHS)
  )
  if(NL3_INCLUDE_DIR)
    find_library(NL3_LIBRARY
      NAMES
        nl-3
      PATH_SUFFIXES
        lib64 lib
      HINTS
        "${NL3_libnl-3.0_LIBDIR}"
      PATHS
        $(SEARCHPATHS)
    )
    find_library(NLGENL_LIBRARY
      NAMES
        nl-genl-3
      PATH_SUFFIXES
        lib64 lib
      HINTS
        "${NL3_libnl-genl-3.0_LIBDIR}"
      PATHS
        $(SEARCHPATHS)
    )
    find_library(NLROUTE_LIBRARY
      NAMES
        nl-route-3
      PATH_SUFFIXES
        lib64 lib
      HINTS
        "${NL3_libnl-route-3.0_LIBDIR}"
      PATHS
        $(SEARCHPATHS)
    )
    #
    # If we don't have all of those libraries, we can't use libnl.
    #
    if(NL3_LIBRARY AND NLGENL_LIBRARY AND NLROUTE_LIBRARY)
      set(NL_LIBRARY ${NL3_LIBRARY})
      if(NL3_INCLUDE_DIR)
        set(HAVE_LIBNL3 1)
      endif()
    endif()
    set(NL_INCLUDE_DIR ${NL3_INCLUDE_DIR})
  endif()

endif()

# handle the QUIETLY and REQUIRED arguments and set NL_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(NL DEFAULT_MSG NL_LIBRARY NL_INCLUDE_DIR)

IF(NL_FOUND)
  set(NL_LIBRARIES ${NLGENL_LIBRARY} ${NLROUTE_LIBRARY} ${NL_LIBRARY})
  set(NL_INCLUDE_DIRS ${NL_INCLUDE_DIR})
  set(HAVE_LIBNL 1)
else()
  set(NL_LIBRARIES )
  set(NL_INCLUDE_DIRS)
endif()

MARK_AS_ADVANCED( NL_LIBRARIES NL_INCLUDE_DIRS )

