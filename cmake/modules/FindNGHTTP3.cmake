# Find the system's Nghttp3 includes and library
#
#  NGHTTP3_INCLUDE_DIRS - where to find nghttp3.h
#  NGHTTP3_LIBRARIES    - List of libraries when using nghttp3
#  NGHTTP3_FOUND        - True if nghttp3 found
#  NGHTTP3_DLL_DIR      - (Windows) Path to the Nghttp2 DLL
#  NGHTTP3_DLL          - (Windows) Name of the Nghttp2 DLL

include( FindWSWinLibs )
FindWSWinLibs( "nghttp3-.*" "NGHTTP3_HINTS" )

if( NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(NGHTTP3 libnghttp3)
endif()

find_path( NGHTTP3_INCLUDE_DIR
  NAMES nghttp3/nghttp3.h
  HINTS
    "${NGHTTP3_INCLUDEDIR}"
    "${NGHTTP3_HINTS}/include"
  PATHS /usr/local/include /usr/include
)

find_library( NGHTTP3_LIBRARY
  NAMES nghttp3
  HINTS
    "${NGHTTP3_LIBDIR}"
    "${NGHTTP3_HINTS}/lib"
  PATHS /usr/local/lib /usr/lib
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( NGHTTP3 DEFAULT_MSG NGHTTP3_LIBRARY NGHTTP3_INCLUDE_DIR )

if( NGHTTP3_FOUND )
  set( NGHTTP3_INCLUDE_DIRS ${NGHTTP3_INCLUDE_DIR} )
  set( NGHTTP3_LIBRARIES ${NGHTTP3_LIBRARY} )
  if (WIN32)
    set ( NGHTTP3_DLL_DIR "${NGHTTP3_HINTS}/bin"
      CACHE PATH "Path to nghttp3 DLL"
    )
    file( GLOB _nghttp3_dll RELATIVE "${NGHTTP3_DLL_DIR}"
      "${NGHTTP3_DLL_DIR}/nghttp3.dll"
    )
    set ( NGHTTP3_DLL ${_nghttp3_dll}
      CACHE FILEPATH "nghttp3 DLL file name"
    )
    file( GLOB _nghttp3_pdb RELATIVE "${NGHTTP3_DLL_DIR}"
      "${NGHTTP3_DLL_DIR}/nghttp3.pdb"
    )
    set ( NGHTTP3_PDB ${_nghttp3_pdb}
      CACHE FILEPATH "nghttp3 PDB file name"
    )
    mark_as_advanced( NGHTTP3_DLL_DIR NGHTTP3_DLL NGHTTP3_PDB )
  endif()
else()
  set( NGHTTP3_INCLUDE_DIRS )
  set( NGHTTP3_LIBRARIES )
endif()

mark_as_advanced( NGHTTP3_LIBRARIES NGHTTP3_INCLUDE_DIRS )
