# Find the system's bcg729 includes and library
#
#  BCG729_INCLUDE_DIRS - where to find bcg729/decoder.h
#  BCG729_LIBRARIES    - List of libraries when using bcg729
#  BCG729_FOUND        - True if bcg729 found
#  BCG729_DLL_DIR      - (Windows) Path to the bcg729 DLL
#  BCG729_DLL          - (Windows) Name of the bcg729 DLL

include( FindWSWinLibs )
FindWSWinLibs( "bcg729-.*" "BCG729_HINTS" )

if (NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(BCG729 bcg729)
endif()

find_path( BCG729_INCLUDE_DIR
  NAMES bcg729/decoder.h
  HINTS
    "${BCG729_INCLUDE_DIR}"
    "${BCG729_HINTS}/include"
  PATHS /usr/local/include /usr/include
)

find_library( BCG729_LIBRARY
  NAMES bcg729
  HINTS
    "${BCG729_LIBDIR}"
    "${BCG729_HINTS}/lib"
  PATHS /usr/local/lib /usr/lib
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( BCG729 DEFAULT_MSG BCG729_LIBRARY BCG729_INCLUDE_DIR )

if( BCG729_FOUND )
  set( BCG729_INCLUDE_DIRS ${BCG729_INCLUDE_DIR} )
  set( BCG729_LIBRARIES ${BCG729_LIBRARY} )
  if (WIN32)
    set ( BCG729_DLL_DIR "${BCG729_HINTS}/bin"
      CACHE PATH "Path to bcg729 DLL"
    )
    file( GLOB _bcg729_dll RELATIVE "${BCG729_DLL_DIR}"
      "${BCG729_DLL_DIR}/libbcg729.dll"
    )
    set ( BCG729_DLL ${_bcg729_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "bcg729 DLL file name"
    )
    mark_as_advanced( BCG729_DLL_DIR BCG729_DLL )
  endif()
else()
  set( BCG729_INCLUDE_DIRS )
  set( BCG729_LIBRARIES )
endif()

mark_as_advanced( BCG729_LIBRARIES BCG729_INCLUDE_DIRS )
