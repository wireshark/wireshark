#
# - Find brotli
# Find brotli includes and libraries
#
#  BROTLI_INCLUDE_DIRS - where to find brotli header files
#  BROTLI_LIBRARIES    - List of libraries when using brotli.
#  BROTLI_FOUND        - True if brotli found.
#  BROTLI_DLL_DIR      - (Windows) Path to the brotli DLLs
#  BROTLI_DLLS         - (Windows) Name of the brotli DLLs

include( FindWSWinLibs )
FindWSWinLibs( "brotli-.*" "BROTLI_HINTS" )

find_path(BROTLI_INCLUDE_DIR
  NAMES "brotli/decode.h"
  HINTS "${BROTLI_HINTS}/include"
)

find_library(BROTLIDEC_LIBRARY
  NAMES brotlidec
  HINTS "${BROTLI_HINTS}/lib"
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args( BROTLI DEFAULT_MSG BROTLIDEC_LIBRARY BROTLI_INCLUDE_DIR )

if( BROTLI_FOUND )
  set( BROTLI_INCLUDE_DIRS ${BROTLI_INCLUDE_DIR} )
  set( BROTLI_LIBRARIES ${BROTLIDEC_LIBRARY} )

  if (WIN32)
    set ( BROTLI_DLL_DIR "${BROTLI_HINTS}/bin"
      CACHE PATH "Path to the brotli DLLs"
    )
    file( GLOB _brotli_dlls RELATIVE "${BROTLI_DLL_DIR}"
      "${BROTLI_DLL_DIR}/brotlicommon*.dll"
      "${BROTLI_DLL_DIR}/brotlidec*.dll"
    )
    set ( BROTLI_DLLS ${_brotli_dlls}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "brotli DLL list"
    )
    mark_as_advanced( BROTLI_DLL_DIR BROTLI_DLLS )
  endif()
else()
  set( BROTLI_INCLUDE_DIRS )
  set( BROTLI_LIBRARIES )
endif()

mark_as_advanced( BROTLI_LIBRARIES BROTLI_INCLUDE_DIRS )
