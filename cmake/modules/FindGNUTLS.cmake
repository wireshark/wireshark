#
# - Find gnutls
# Find the native GNUTLS includes and library
#
#  GNUTLS_INCLUDE_DIRS - where to find gnutls.h, etc.
#  GNUTLS_LIBRARIES    - List of libraries when using gnutls.
#  GNUTLS_FOUND        - True if gnutls found.
#  GNUTLS_DLL_DIR      - (Windows) Path to the GnuTLS DLLs.
#  GNUTLS_DLLS         - (Windows) List of required GnuTLS DLLs.


if(GNUTLS_INCLUDE_DIRS)
  # Already in cache, be silent
  set(GNUTLS_FIND_QUIETLY TRUE)
endif()

include(FindWSWinLibs)
findwswinlibs("gnutls-.*" "GNUTLS_HINTS")

if(NOT USE_REPOSITORY)
  find_package(PkgConfig)
  pkg_search_module(GNUTLS gnutls)
endif()

# sources include gnutls/gnutls.h, look for that location instead of gnutls.h.
find_path(GNUTLS_INCLUDE_DIR
  NAMES
    gnutls/gnutls.h
  HINTS
    "${GNUTLS_INCLUDEDIR}"
    "${GNUTLS_HINTS}/include"
)

find_library(GNUTLS_LIBRARY
  NAMES
    gnutls libgnutls-28 libgnutls-30
  HINTS
    "${GNUTLS_LIBDIR}"
    "${GNUTLS_HINTS}/lib"
)

# On systems without pkg-config (e.g. Windows), search its header
# (available since GnuTLS 0.1.3)
if(NOT GNUTLS_VERSION)
  if(GNUTLS_INCLUDE_DIR)
    set(_version_regex "^#define[ \t]+GNUTLS_VERSION[ \t]+\"([^\"]+)\".*")
    file(STRINGS "${GNUTLS_INCLUDE_DIR}/gnutls/gnutls.h" GNUTLS_VERSION REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" GNUTLS_VERSION "${GNUTLS_VERSION}")
    unset(_version_regex)
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GNUTLS
  REQUIRED_VARS   GNUTLS_LIBRARY GNUTLS_INCLUDE_DIR
  VERSION_VAR     GNUTLS_VERSION)

if(GNUTLS_FOUND)
  set(GNUTLS_LIBRARIES ${GNUTLS_LIBRARY})
  set(GNUTLS_INCLUDE_DIRS ${GNUTLS_INCLUDE_DIR})
  AddWSWinDLLS(GNUTLS GNUTLS_HINTS "libgmp-*" "libgcc_s_*" "libffi-*" "libgnutls-*" "libhogweed-*" "libiconv-*" "libintl-*" "libnettle-*" "libp11-kit-*" "libtasn1-*" "libwinpthread-*")
else()
  set(GNUTLS_LIBRARIES)
  set(GNUTLS_INCLUDE_DIRS)
  set(GNUTLS_DLL_DIR)
  set(GNUTLS_DLLS)
endif()

mark_as_advanced(GNUTLS_LIBRARIES GNUTLS_INCLUDE_DIRS)
