# Find the system's Nghttp2 includes and library
#
#  NGHTTP2_INCLUDE_DIRS - where to find nghttp2.h
#  NGHTTP2_LIBRARIES    - List of libraries when using nghttp2
#  NGHTTP2_FOUND        - True if nghttp2 found
#  NGHTTP2_DLL_DIR      - (Windows) Path to the Nghttp2 DLL
#  NGHTTP2_DLL          - (Windows) Name of the Nghttp2 DLL

include( FindWSWinLibs )
FindWSWinLibs( "nghttp2-.*" "NGHTTP2_HINTS" )

if( NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(NGHTTP2 libnghttp2)
endif()

find_path( NGHTTP2_INCLUDE_DIR
  NAMES nghttp2/nghttp2.h
  HINTS
    "${NGHTTP2_INCLUDEDIR}"
    "${NGHTTP2_HINTS}/include"
  PATHS /usr/local/include /usr/include
)

find_library( NGHTTP2_LIBRARY
  NAMES nghttp2
  HINTS
    "${NGHTTP2_LIBDIR}"
    "${NGHTTP2_HINTS}/lib"
  PATHS /usr/local/lib /usr/lib
)

include( FindPackageHandleStandardArgs )
find_package_handle_standard_args( NGHTTP2 DEFAULT_MSG NGHTTP2_LIBRARY NGHTTP2_INCLUDE_DIR )

if( NGHTTP2_FOUND )
  set( NGHTTP2_INCLUDE_DIRS ${NGHTTP2_INCLUDE_DIR} )
  set( NGHTTP2_LIBRARIES ${NGHTTP2_LIBRARY} )
  if (WIN32)
    set ( NGHTTP2_DLL_DIR "${NGHTTP2_HINTS}/bin"
      CACHE PATH "Path to nghttp2 DLL"
    )
    file( GLOB _nghttp2_dll RELATIVE "${NGHTTP2_DLL_DIR}"
      "${NGHTTP2_DLL_DIR}/nghttp2.dll"
    )
    set ( NGHTTP2_DLL ${_nghttp2_dll}
      CACHE FILEPATH "nghttp2 DLL file name"
    )
    file( GLOB _nghttp2_pdb RELATIVE "${NGHTTP2_DLL_DIR}"
      "${NGHTTP2_DLL_DIR}/nghttp2.pdb"
    )
    set ( NGHTTP2_PDB ${_nghttp2_pdb}
      CACHE FILEPATH "nghttp2 PDB file name"
    )
    mark_as_advanced( NGHTTP2_DLL_DIR NGHTTP2_DLL NGHTTP2_PDB )
  endif()
else()
  set( NGHTTP2_INCLUDE_DIRS )
  set( NGHTTP2_LIBRARIES )
endif()

mark_as_advanced( NGHTTP2_LIBRARIES NGHTTP2_INCLUDE_DIRS )
