#
# - Find lz4
# Find LZ4 includes and library
#
#  LZ4_INCLUDE_DIRS - where to find lz4.h, etc.
#  LZ4_LIBRARIES    - List of libraries when using lz4.
#  LZ4_FOUND        - True if lz4 found.

find_package(PkgConfig)
pkg_search_module(LZ4 lz4 liblz4)

find_path(LZ4_INCLUDE_DIR
  NAMES lz4.h
  HINTS "${LZ4_INCLUDEDIR}"
  PATHS
  /usr/local/include
  /usr/include
)

find_library(LZ4_LIBRARY
  NAMES lz4 liblz4
  HINTS "${LZ4_LIBDIR}"
  PATHS
  /usr/local/lib
  /usr/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args( LZ4 DEFAULT_MSG LZ4_INCLUDE_DIR LZ4_LIBRARY )

if( LZ4_FOUND )
  set( LZ4_INCLUDE_DIRS ${LZ4_INCLUDE_DIR} )
  set( LZ4_LIBRARIES ${LZ4_LIBRARY} )
else()
  set( LZ4_INCLUDE_DIRS )
  set( LZ4_LIBRARIES )
endif()

mark_as_advanced( LZ4_LIBRARIES LZ4_INCLUDE_DIRS )
