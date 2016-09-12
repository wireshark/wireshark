#
# Find the native netlink includes and library
#
# If they exist, differentiate between versions 1, 2 and 3.
# Version 1 does not have netlink/version.h
# Version 2 started separating libraries (libnl{,-genl,-route}).
# Version 3 (>= 3.2) started appending the major version number as suffix to
# library names (libnl-3)
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
  if(NOT NL3_FOUND)
    pkg_search_module(NL2 libnl-2.0)
  endif()

  # Try to find NL 2.0, 3.0 or 3.1 (/usr/include/netlink/version.h) or
  # NL >= 3.2 (/usr/include/libnl3/netlink/version.h)
  find_path(NL3_INCLUDE_DIR
    PATH_SUFFIXES
      include/libnl3
      include
    NAMES
      netlink/version.h
    HINTS
      "${NL3_libnl-3.0_INCLUDEDIR}"
      "${NL2_INCLUDEDIR}"
    PATHS
      $(SEARCHPATHS)
  )
  # NL version >= 2
  if(NL3_INCLUDE_DIR)
    find_library(NL3_LIBRARY
      NAMES
        nl-3 nl
      PATH_SUFFIXES
        lib64 lib
      HINTS
        "${NL3_libnl-3.0_LIBDIR}"
        "${NL2_LIBDIR}"
      PATHS
        $(SEARCHPATHS)
    )
    find_library(NLGENL_LIBRARY
      NAMES
        nl-genl-3 nl-genl
      PATH_SUFFIXES
        lib64 lib
      HINTS
        "${NL3_libnl-genl-3.0_LIBDIR}"
        "${NL2_LIBDIR}"
      PATHS
        $(SEARCHPATHS)
    )
    find_library(NLROUTE_LIBRARY
      NAMES
        nl-route-3 nl-route
      PATH_SUFFIXES
        lib64 lib
      HINTS
        "${NL3_libnl-route-3.0_LIBDIR}"
        "${NL2_LIBDIR}"
      PATHS
        $(SEARCHPATHS)
    )
    #
    # If we don't have all of those libraries, we can't use libnl.
    #
    if(NL3_LIBRARY AND NLGENL_LIBRARY AND NLROUTE_LIBRARY)
      set(NL_LIBRARY ${NL3_LIBRARY})
      if(NL3_INCLUDE_DIR)
        # NL2 and NL3 are similar and just affect how the version is reported in
        # the --version output. In cast of doubt, assume NL3 since a library
        # without version number could be any of 2.0, 3.0 or 3.1.
        if(NOT NL3_FOUND AND NL2_FOUND)
          set(HAVE_LIBNL2 1)
        else()
          set(HAVE_LIBNL3 1)
        endif()
      endif()
    endif()
    set(NL_INCLUDE_DIR ${NL3_INCLUDE_DIR})
  endif()

  # libnl-2 and libnl-3 not found, try NL version 1
  if(NOT (NL_LIBRARY AND NL_INCLUDE_DIR))
    pkg_search_module(NL1 libnl-1)
    find_path(NL1_INCLUDE_DIR
      NAMES
        netlink/netlink.h
      HINTS
        "${NL1_INCLUDEDIR}"
      PATHS
        $(SEARCHPATHS)
    )
    find_library(NL1_LIBRARY
      NAMES
        nl
      PATH_SUFFIXES
        lib64 lib
      HINTS
        "${NL1_LIBDIR}"
      PATHS
        $(SEARCHPATHS)
    )
    set(NL_LIBRARY ${NL1_LIBRARY})
    set(NL_INCLUDE_DIR ${NL1_INCLUDE_DIR})
    if(NL1_LIBRARY AND NL1_INCLUDE_DIR)
      set(HAVE_LIBNL1 1)
    endif()
  endif()
endif()
# MESSAGE(STATUS "LIB Found: ${NL_LIBRARY}, Suffix: ${NLSUFFIX}\n  1:${HAVE_LIBNL1}, 2:${HAVE_LIBNL2}, 3:${HAVE_LIBNL3}.")

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

