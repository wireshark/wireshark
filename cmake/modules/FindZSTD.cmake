#
# - Find zstd
# Find Zstd includes and library
#
#  ZSTD_INCLUDE_DIRS - where to find zstd.h, etc.
#  ZSTD_LIBRARIES    - List of libraries when using Zstd.
#  ZSTD_FOUND        - True if Zstd found.
#  ZSTD_DLL_DIR      - (Windows) Path to the Zstd DLL
#  ZSTD_DLL          - (Windows) Name of the Zstd DLL

include( FindWSWinLibs )
FindWSWinLibs( "zstd-.*" "ZSTD_HINTS" )

if( NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(ZSTD libzstd)
endif()

find_path(ZSTD_INCLUDE_DIR
  NAMES zstd.h
  HINTS "${ZSTD_INCLUDEDIR}" "${ZSTD_HINTS}/include"
  /usr/include
  /usr/local/include
)

find_library(ZSTD_LIBRARY
  NAMES zstd
  HINTS "${ZSTD_LIBDIR}" "${ZSTD_HINTS}/lib"
  PATHS
  /usr/lib
  /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args( ZSTD DEFAULT_MSG ZSTD_LIBRARY ZSTD_INCLUDE_DIR )

if( ZSTD_FOUND )
  set( ZSTD_INCLUDE_DIRS ${ZSTD_INCLUDE_DIR} )
  set( ZSTD_LIBRARIES ${ZSTD_LIBRARY} )
  if (WIN32)
    set ( ZSTD_DLL_DIR "${ZSTD_HINTS}/bin"
      CACHE PATH "Path to Zstd DLL"
    )
    file( GLOB _zstd_dll RELATIVE "${ZSTD_DLL_DIR}"
      "${ZSTD_DLL_DIR}/zstd*.dll"
    )
    set ( ZSTD_DLL ${_zstd_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "Zstd DLL file name"
    )
    mark_as_advanced( ZSTD_DLL_DIR ZSTD_DLL )
  endif()
else()
  set( ZSTD_INCLUDE_DIRS )
  set( ZSTD_LIBRARIES )
endif()

mark_as_advanced( ZSTD_LIBRARIES ZSTD_INCLUDE_DIRS )
