#
# - Find gcrypt
# Find the native GCRYPT includes and library
#
#  GCRYPT_INCLUDE_DIRS - where to find gcrypt.h, etc.
#  GCRYPT_LIBRARIES    - List of libraries when using gcrypt.
#  GCRYPT_FOUND        - True if gcrypt found.
#  GCRYPT_DLL_DIR      - (Windows) Path to the Libgcrypt DLLs.
#  GCRYPT_DLLS         - (Windows) List of required Libgcrypt DLLs.


IF (GCRYPT_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(GCRYPT_FIND_QUIETLY TRUE)
ENDIF (GCRYPT_INCLUDE_DIRS)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("gnutls-.*" "GCRYPT_HINTS")

FIND_PATH(GCRYPT_INCLUDE_DIR gcrypt.h
  HINTS
    "${GCRYPT_HINTS}"
  PATH_SUFFIXES
    include
)

SET(GCRYPT_NAMES gcrypt libgcrypt-20)
FIND_LIBRARY(GCRYPT_LIBRARY NAMES ${GCRYPT_NAMES} libgcc_s_sjlj-1 HINTS "${GCRYPT_HINTS}/bin")
FIND_LIBRARY(GCRYPT_ERROR_LIBRARY NAMES gpg-error libgpg-error-0 libgpg-error6-0 HINTS "${GCRYPT_HINTS}/bin")

# Try to retrieve version from header if found (available since libgcrypt 1.3.0)
if(GCRYPT_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+GCRYPT_VERSION[ \t]+\"([^\"]+)\".*")
  file(STRINGS "${GCRYPT_INCLUDE_DIR}/gcrypt.h" GCRYPT_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1" GCRYPT_VERSION "${GCRYPT_VERSION}")
  unset(_version_regex)
endif()

# handle the QUIETLY and REQUIRED arguments and set GCRYPT_FOUND to TRUE if
# all listed variables are TRUE and the requested version matches.
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GCRYPT
  REQUIRED_VARS   GCRYPT_LIBRARY GCRYPT_INCLUDE_DIR
  VERSION_VAR     GCRYPT_VERSION)

IF(GCRYPT_FOUND)
  SET( GCRYPT_LIBRARIES ${GCRYPT_LIBRARY} ${GCRYPT_ERROR_LIBRARY})
  SET( GCRYPT_INCLUDE_DIRS ${GCRYPT_INCLUDE_DIR})
  if (WIN32)
    set ( GCRYPT_DLL_DIR "${GCRYPT_HINTS}/bin"
      CACHE PATH "Path to the Libgcrypt DLLs"
    )
    file( GLOB _gcrypt_dlls RELATIVE "${GCRYPT_DLL_DIR}"
      "${GCRYPT_DLL_DIR}/libgcc_s_*.dll"
      "${GCRYPT_DLL_DIR}/libgcrypt-*.dll"
      "${GCRYPT_DLL_DIR}/libgpg-error*.dll"
    )
    set ( GCRYPT_DLLS ${_gcrypt_dlls}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "Libgcrypt DLL list"
    )
    mark_as_advanced( GCRYPT_DLL_DIR GCRYPT_DLLS )
  endif()
ELSE(GCRYPT_FOUND)
  SET( GCRYPT_LIBRARIES )
  SET( GCRYPT_INCLUDE_DIRS )
  SET( GCRYPT_DLL_DIR )
  SET( GCRYPT_DLLS )
ENDIF(GCRYPT_FOUND)

MARK_AS_ADVANCED( GCRYPT_LIBRARIES GCRYPT_INCLUDE_DIRS )
