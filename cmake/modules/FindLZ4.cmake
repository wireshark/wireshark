#
# - Find lz4
# Find LZ4 includes and library
#
#  LZ4_INCLUDE_DIRS - where to find lz4.h, etc.
#  LZ4_LIBRARIES    - List of libraries when using LZ4.
#  LZ4_FOUND        - True if LZ4 found.
#  LZ4_DLL_DIR      - (Windows) Path to the LZ4 DLL
#  LZ4_DLL          - (Windows) Name of the LZ4 DLL

include( FindWSWinLibs )
FindWSWinLibs( "lz4-.*" "LZ4_HINTS" )

find_package(PkgConfig)
pkg_search_module(LZ4 lz4 liblz4)

find_path(LZ4_INCLUDE_DIR
  NAMES lz4.h
  HINTS "${LZ4_INCLUDEDIR}" "${LZ4_HINTS}/include"
  PATHS
  /usr/local/include
  /usr/include
)

find_library(LZ4_LIBRARY
  NAMES lz4 liblz4
  HINTS "${LZ4_LIBDIR}" "${LZ4_HINTS}/lib"
  PATHS
  /usr/local/lib
  /usr/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args( LZ4 DEFAULT_MSG LZ4_INCLUDE_DIR LZ4_LIBRARY )

if( LZ4_FOUND )
  set( LZ4_INCLUDE_DIRS ${LZ4_INCLUDE_DIR} )
  set( LZ4_LIBRARIES ${LZ4_LIBRARY} )
  if (WIN32)
    set ( LZ4_DLL_DIR "${LZ4_HINTS}/bin"
      CACHE PATH "Path to LZ4 DLL"
    )
    file( GLOB _lz4_dll RELATIVE "${LZ4_DLL_DIR}"
      "${LZ4_DLL_DIR}/liblz4*.dll"
    )
    set ( LZ4_DLL ${_lz4_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "LZ4 DLL file name"
    )
    mark_as_advanced( LZ4_DLL_DIR LZ4_DLL )
  endif()
else()
  set( LZ4_INCLUDE_DIRS )
  set( LZ4_LIBRARIES )
endif()

mark_as_advanced( LZ4_LIBRARIES LZ4_INCLUDE_DIRS )
