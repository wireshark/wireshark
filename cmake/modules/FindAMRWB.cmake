# Find the system's opencore-amrwb includes and library
#
#  AMRWB_INCLUDE_DIRS - where to find amrwb/decoder.h
#  AMRWB_LIBRARIES    - List of libraries when using amrwb
#  AMRWB_FOUND        - True if amrwb found
#  AMRWB_DLL_DIR      - (Windows) Path to the amrwb DLL
#  AMRWB_DLL          - (Windows) Name of the amrwb DLL

include( FindWSWinLibs )
FindWSWinLibs( "opencore-amr-.*" "AMRWB_HINTS" )

if (NOT USE_REPOSITORY)
  find_package(PkgConfig)
  pkg_search_module(PC_AMRWB opencore-amrwb)
endif()

find_path( AMRWB_INCLUDE_DIR
  NAMES opencore-amrwb/dec_if.h
  HINTS
    "${PC_AMRWB_INCLUDE_DIRS}"
    "${AMRWB_HINTS}/include"
  PATHS /usr/local/include /usr/include
)

find_library( AMRWB_LIBRARY
  NAMES opencore-amrwb libopencore-amrwb-0
  HINTS
    "${PC_AMRWB_LIBDIRS}"
    "${AMRWB_HINTS}/lib"
  PATHS /usr/local/lib /usr/lib
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( AMRWB DEFAULT_MSG AMRWB_LIBRARY AMRWB_INCLUDE_DIR)

if( AMRWB_FOUND )
  set( AMRWB_INCLUDE_DIRS ${AMRWB_INCLUDE_DIR} )
  set( AMRWB_LIBRARIES ${AMRWB_LIBRARY} )
  if (WIN32)
    set ( AMRWB_DLL_DIR "${AMRWB_HINTS}/bin"
      CACHE PATH "Path to the AMRWB DLL"
    )
    file( GLOB _amrwb_dll RELATIVE "${AMRWB_DLL_DIR}"
      "${AMRWB_DLL_DIR}/libopencore-amrwb-0.dll"
    )
    set ( AMRWB_DLL ${_amrwb_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "AMR WB-DLL file name"
    )
    mark_as_advanced( AMRWB_DLL_DIR AMRWB_DLL )
  endif()
else()
  set( AMRWB_INCLUDE_DIRS )
  set( AMRWB_LIBRARIES )
endif()

mark_as_advanced( AMRWB_LIBRARIES AMRWB_INCLUDE_DIRS )