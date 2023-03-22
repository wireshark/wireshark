# Find the system's opencore-amrnb includes and library
#
#  AMRNB_INCLUDE_DIRS - where to find amrnb/decoder.h
#  AMRNB_LIBRARIES    - List of libraries when using amrnb
#  AMRNB_FOUND        - True if amrnb found
#  AMRNB_DLL_DIR      - (Windows) Path to the amrnb DLL
#  AMRNB_DLL          - (Windows) Name of the amrnb DLL

include( FindWSWinLibs )
FindWSWinLibs( "opencore-amrnb-.*" "AMRNB_HINTS" )

if (NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(AMRNB opencore-amrnb)
endif()

find_path( AMRNB_INCLUDE_DIR
  NAMES opencore-amrnb/interf_dec.h
  HINTS
    "${AMRNB_INCLUDE_DIR}"
    "${AMRNB_HINTS}/include"
  PATHS /usr/local/include /usr/include
)

find_library( AMRNB_LIBRARY
  NAMES opencore-amrnb
  HINTS
    "${AMRNB_LIBDIR}"
    "${AMRNB_HINTS}/lib"
  PATHS /usr/local/lib /usr/lib
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( AMRNB DEFAULT_MSG AMRNB_INCLUDE_DIR AMRNB_LIBRARY )

if( AMRNB_FOUND )
  set( AMRNB_INCLUDE_DIRS ${AMRNB_INCLUDE_DIR} )
  set( AMRNB_LIBRARIES ${AMRNB_LIBRARY} )
  if (WIN32)
    set ( AMRNB_DLL_DIR "${AMRNB_HINTS}/bin"
      CACHE PATH "Path to amrnb DLL"
    )
    file( GLOB _amrnb_dll RELATIVE "${AMRNB_DLL_DIR}"
      "${AMRNB_DLL_DIR}/libamrnb.dll"
    )
    set ( AMRNB_DLL ${_amrnb_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "amrnb DLL file name"
    )
    mark_as_advanced( AMRNB_DLL_DIR AMRNB_DLL )
  endif()
else()
  set( AMRNB_INCLUDE_DIRS )
  set( AMRNB_LIBRARIES )
endif()

mark_as_advanced( AMRNB_LIBRARIES AMRNB_INCLUDE_DIRS )
