#
# - Find gnutls
# Find the native GNUTLS includes and library
#
#  GNUTLS_INCLUDE_DIRS - where to find gnutls.h, etc.
#  GNUTLS_LIBRARIES    - List of libraries when using gnutls.
#  GNUTLS_FOUND        - True if gnutls found.
#  GNUTLS_DLL_DIR      - (Windows) Path to the GnuTLS DLLs.
#  GNUTLS_DLLS         - (Windows) List of required GnuTLS DLLs.


IF (GNUTLS_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(GNUTLS_FIND_QUIETLY TRUE)
ENDIF (GNUTLS_INCLUDE_DIRS)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("gnutls-.*" "GNUTLS_HINTS")

find_package(PkgConfig)
pkg_search_module(GNUTLS gnutls)

FIND_PATH(GNUTLS_INCLUDE_DIR
  NAMES
    gnutls.h
    gnutls/gnutls.h
  PATH_SUFFIXES
    include
  HINTS
    "${GNUTLS_INCLUDEDIR}"
    "${GNUTLS_HINTS}"
)

SET(GNUTLS_NAMES gnutls libgnutls-28)
FIND_LIBRARY(GNUTLS_LIBRARY
  NAMES
    ${GNUTLS_NAMES}
    libgmp-10 libgcc_s_sjlj-1 libffi-6 libhogweed-2-4 libnettle-4-6
    libp11-kit-0 libtasn1-6
  HINTS
    "${GNUTLS_LIBDIR}"
    "${GNUTLS_HINTS}/bin"
)

# handle the QUIETLY and REQUIRED arguments and set GNUTLS_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GNUTLS DEFAULT_MSG GNUTLS_LIBRARY GNUTLS_INCLUDE_DIR)

IF(GNUTLS_FOUND)
  SET( GNUTLS_LIBRARIES ${GNUTLS_LIBRARY} )
  SET( GNUTLS_INCLUDE_DIRS ${GNUTLS_INCLUDE_DIR} )
  if (WIN32)
    set ( GNUTLS_DLL_DIR "${GNUTLS_HINTS}/bin"
      CACHE PATH "Path to the GnuTLS DLLs"
    )
    file( GLOB _gnutls_dlls RELATIVE "${GNUTLS_DLL_DIR}"
      "${GNUTLS_DLL_DIR}/libgmp-*.dll"
      "${GNUTLS_DLL_DIR}/libgcc_s_*.dll"
      "${GNUTLS_DLL_DIR}/libffi-*.dll"
      "${GNUTLS_DLL_DIR}/libgnutls-*.dll"
      "${GNUTLS_DLL_DIR}/libhogweed-*.dll"
      "${GNUTLS_DLL_DIR}/libnettle-*.dll"
      "${GNUTLS_DLL_DIR}/libp11-kit-*.dll"
      "${GNUTLS_DLL_DIR}/libtasn1-*.dll"
    )
    set ( GNUTLS_DLLS ${_gnutls_dlls}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "GnuTLS DLL list"
    )
    mark_as_advanced( GNUTLS_DLL_DIR GNUTLS_DLLS )
  endif()
ELSE(GNUTLS_FOUND)
  SET( GNUTLS_LIBRARIES )
  SET( GNUTLS_INCLUDE_DIRS )
  SET( GNUTLS_DLL_DIR )
  SET( GNUTLS_DLLS )
ENDIF(GNUTLS_FOUND)

MARK_AS_ADVANCED( GNUTLS_LIBRARIES GNUTLS_INCLUDE_DIRS )
