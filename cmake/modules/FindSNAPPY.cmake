#
# - Find snappy
# Find Snappy includes and library
#
#  SNAPPY_INCLUDE_DIRS - where to find snappy.h, etc.
#  SNAPPY_LIBRARIES    - List of libraries when using snappy.
#  SNAPPY_FOUND        - True if snappy found.

find_package(PkgConfig)
pkg_search_module(SNAPPY libsnappy)

find_path(SNAPPY_INCLUDE_DIR
  NAMES snappy.h
  HINTS "${SNAPPY_INCLUDEDIR}"
  /usr/include
  /usr/local/include
)

find_library(SNAPPY_LIBRARY
  NAMES snappy
  HINTS "${SNAPPY_LIBDIR}"
  PATHS
  /usr/lib
  /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args( SNAPPY DEFAULT_MSG SNAPPY_INCLUDE_DIR SNAPPY_LIBRARY )

if( SNAPPY_FOUND )
  set( SNAPPY_INCLUDE_DIRS ${SNAPPY_INCLUDE_DIR} )
  set( SNAPPY_LIBRARIES ${SNAPPY_LIBRARY} )
else()
  set( SNAPPY_INCLUDE_DIRS )
  set( SNAPPY_LIBRARIES )
endif()

mark_as_advanced( SNAPPY_LIBRARIES SNAPPY_INCLUDE_DIRS )
