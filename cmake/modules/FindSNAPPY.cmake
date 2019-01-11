#
# - Find snappy
# Find Snappy includes and library
#
#  SNAPPY_INCLUDE_DIRS - where to find snappy.h, etc.
#  SNAPPY_LIBRARIES    - List of libraries when using Snappy.
#  SNAPPY_FOUND        - True if Snappy found.
#  SNAPPY_DLL_DIR      - (Windows) Path to the Snappy DLL
#  SNAPPY_DLL          - (Windows) Name of the Snappy DLL

include( FindWSWinLibs )
FindWSWinLibs( "snappy-.*" "SNAPPY_HINTS" )

if( NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(SNAPPY libsnappy)
endif()

find_path(SNAPPY_INCLUDE_DIR
  NAMES snappy.h
  HINTS "${SNAPPY_INCLUDEDIR}" "${SNAPPY_HINTS}/include"
  /usr/include
  /usr/local/include
)

find_library(SNAPPY_LIBRARY
  NAMES snappy
  HINTS "${SNAPPY_LIBDIR}" "${SNAPPY_HINTS}/lib"
  PATHS
  /usr/lib
  /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args( SNAPPY DEFAULT_MSG SNAPPY_LIBRARY SNAPPY_INCLUDE_DIR )

if( SNAPPY_FOUND )
  set( SNAPPY_INCLUDE_DIRS ${SNAPPY_INCLUDE_DIR} )
  set( SNAPPY_LIBRARIES ${SNAPPY_LIBRARY} )
  if (WIN32)
    set ( SNAPPY_DLL_DIR "${SNAPPY_HINTS}/bin"
      CACHE PATH "Path to Snappy DLL"
    )
    file( GLOB _snappy_dll RELATIVE "${SNAPPY_DLL_DIR}"
      "${SNAPPY_DLL_DIR}/libsnappy-*.dll"
    )
    set ( SNAPPY_DLL ${_snappy_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "Snappy DLL file name"
    )
    mark_as_advanced( SNAPPY_DLL_DIR SNAPPY_DLL )
  endif()
else()
  set( SNAPPY_INCLUDE_DIRS )
  set( SNAPPY_LIBRARIES )
endif()

mark_as_advanced( SNAPPY_LIBRARIES SNAPPY_INCLUDE_DIRS )
