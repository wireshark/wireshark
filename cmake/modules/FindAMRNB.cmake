# Find the system's opencore-amrnb includes and library
#
#  AMRNB_INCLUDE_DIRS - where to find amrnb/decoder.h
#  AMRNB_LIBRARIES    - List of libraries when using amrnb
#  AMRNB_FOUND        - True if amrnb found
#  AMRNB_DLL_DIR      - (Windows) Path to the amrnb DLL
#  AMRNB_DLL          - (Windows) Name of the amrnb DLL

include( FindWSWinLibs )
FindWSWinLibs( "opencore-amr-.*" "AMRNB_HINTS" )

if (NOT USE_REPOSITORY)
  find_package(PkgConfig)
  pkg_search_module(PC_AMRNB opencore-amrnb)
endif()

find_path( AMRNB_INCLUDE_DIR
  NAMES opencore-amrnb/interf_dec.h
  HINTS
    "${PC_AMRNB_INCLUDE_DIRS}"
    "${AMRNB_HINTS}/include"
  PATHS /usr/local/include /usr/include
)

find_library( AMRNB_LIBRARY
  NAMES opencore-amrnb libopencore-amrnb-0
  HINTS
    "${PC_AMRNB_LIBDIRS}"
    "${AMRNB_HINTS}/lib"
  PATHS /usr/local/lib /usr/lib
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( AMRNB DEFAULT_MSG AMRNB_LIBRARY AMRNB_INCLUDE_DIR)

if( AMRNB_FOUND )
  set( AMRNB_INCLUDE_DIRS ${AMRNB_INCLUDE_DIR} )
  set( AMRNB_LIBRARIES ${AMRNB_LIBRARY} )
  if (WIN32)
    set ( AMRNB_DLL_DIR "${AMRNB_HINTS}/bin"
      CACHE PATH "Path to the AMR-NB DLL"
    )
    file( GLOB _amrnb_dll RELATIVE "${AMRNB_DLL_DIR}"
      "${AMRNB_DLL_DIR}/libopencore-amrnb-0.dll"
    )
    set ( AMRNB_DLL ${_amrnb_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "AMR NB-DLL file name"
    )
    mark_as_advanced( AMRNB_DLL_DIR AMRNB_DLL )
  endif()
else()
  set( AMRNB_INCLUDE_DIRS )
  set( AMRNB_LIBRARIES )
endif()

mark_as_advanced( AMRNB_LIBRARIES AMRNB_INCLUDE_DIRS )
