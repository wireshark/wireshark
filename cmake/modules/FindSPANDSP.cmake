# Find the system's SpanDSP includes and library
#
#  SPANDSP_INCLUDE_DIRS - where to find spandsp.h
#  SPANDSP_LIBRARIES    - List of libraries when using SpanDSP
#  SPANDSP_FOUND        - True if SpanDSP found
#  SPANDSP_DLL_DIR      - (Windows) Path to the SpanDSP DLL
#  SPANDSP_DLL          - (Windows) Name of the SpanDSP DLL

include( FindWSWinLibs )
FindWSWinLibs( "spandsp-.*" "SPANDSP_HINTS" )

if( NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(SPANDSP spandsp)
endif()

find_path( SPANDSP_INCLUDE_DIR
  NAMES spandsp.h
  HINTS
    "${SPANDSP_INCLUDEDIR}"
    "${SPANDSP_HINTS}/include"
  PATHS /usr/local/include /usr/include
)

find_library( SPANDSP_LIBRARY
  NAMES spandsp
  HINTS
    "${SPANDSP_LIBDIR}"
    "${SPANDSP_HINTS}/lib"
  PATHS /usr/local/lib /usr/lib
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( SPANDSP DEFAULT_MSG SPANDSP_LIBRARY SPANDSP_INCLUDE_DIR )

if( SPANDSP_FOUND )
  set( SPANDSP_INCLUDE_DIRS ${SPANDSP_INCLUDE_DIR} )
  set( SPANDSP_LIBRARIES ${SPANDSP_LIBRARY} )
  if (WIN32)
    set ( SPANDSP_DLL_DIR "${SPANDSP_HINTS}/bin"
      CACHE PATH "Path to SpanDSP DLL"
    )
    file( GLOB _spandsp_dll RELATIVE "${SPANDSP_DLL_DIR}"
      "${SPANDSP_DLL_DIR}/libspandsp-*.dll"
    )
    set ( SPANDSP_DLL ${_spandsp_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "SpanDSP DLL file name"
    )
    mark_as_advanced( SPANDSP_DLL_DIR SPANDSP_DLL )
  endif()
else()
  set( SPANDSP_INCLUDE_DIRS )
  set( SPANDSP_LIBRARIES )
endif()

mark_as_advanced( SPANDSP_LIBRARIES SPANDSP_INCLUDE_DIRS )
