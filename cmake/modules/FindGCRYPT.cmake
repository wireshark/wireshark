#
# - Find gcrypt
# Find the native GCRYPT includes and library
#
#  GCRYPT_INCLUDE_DIRS - where to find gcrypt.h, etc.
#  GCRYPT_LIBRARIES    - List of libraries when using gcrypt.
#  GCRYPT_FOUND        - True if gcrypt found.
#  GCRYPT_DLL_DIR      - (Windows) Path to the Libgcrypt DLLs.
#  GCRYPT_DLLS         - (Windows) List of required Libgcrypt DLLs.


if(GCRYPT_INCLUDE_DIRS)
  # Already in cache, be silent
  set(GCRYPT_FIND_QUIETLY TRUE)
endif()

include(FindWSWinLibs)
FindWSWinLibs("libgcrypt-.*" "GCRYPT_HINTS")

find_path(GCRYPT_INCLUDE_DIR gcrypt.h
  HINTS
    "${GCRYPT_HINTS}/include"
)

# libgcrypt-20 is used in libgcrypt-1.8.3-win??ws (from Debian).
# libgcrypt is used in libgcrypt-1.10.1-2-win??ws (from Debian).
find_library(GCRYPT_LIBRARY
  NAMES gcrypt libgcrypt libgcrypt-20
  HINTS "${GCRYPT_HINTS}/lib")

# libgpg-error6-0 is used in libgcrypt-1.7.6-win??ws (built from source).
# libgpg-error-0 is used in libgcrypt-1.8.3-win??ws (from Debian).
# libgpg-error is used in libgcrypt-1.10.1-2-win??ws (from Debian).
find_library(GCRYPT_ERROR_LIBRARY
  NAMES gpg-error libgpg-error libgpg-error-0 libgpg-error6-0
  HINTS "${GCRYPT_HINTS}/lib")

# Try to retrieve version from header if found (available since libgcrypt 1.3.0)
if(GCRYPT_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+GCRYPT_VERSION[ \t]+\"([^\"]+)\".*")
  file(STRINGS "${GCRYPT_INCLUDE_DIR}/gcrypt.h" GCRYPT_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1" GCRYPT_VERSION "${GCRYPT_VERSION}")
  unset(_version_regex)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GCRYPT
  REQUIRED_VARS   GCRYPT_LIBRARY GCRYPT_INCLUDE_DIR
  VERSION_VAR     GCRYPT_VERSION)

if(GCRYPT_FOUND)
  set(GCRYPT_LIBRARIES ${GCRYPT_LIBRARY} ${GCRYPT_ERROR_LIBRARY})
  set(GCRYPT_INCLUDE_DIRS ${GCRYPT_INCLUDE_DIR})
  if(WIN32)
    set(GCRYPT_DLL_DIR "${GCRYPT_HINTS}/bin"
      CACHE PATH "Path to the Libgcrypt DLLs"
    )
    file(GLOB _gcrypt_dlls RELATIVE "${GCRYPT_DLL_DIR}"
      "${GCRYPT_DLL_DIR}/libgcrypt-*.dll"
      "${GCRYPT_DLL_DIR}/libgpg-error*.dll"
    )
    set(GCRYPT_DLLS ${_gcrypt_dlls}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "Libgcrypt DLL list"
    )
    mark_as_advanced(GCRYPT_DLL_DIR GCRYPT_DLLS)
  endif()
else()
  set(GCRYPT_LIBRARIES)
  set(GCRYPT_INCLUDE_DIRS)
  set(GCRYPT_DLL_DIR)
  set(GCRYPT_DLLS)
endif()

mark_as_advanced(GCRYPT_LIBRARIES GCRYPT_INCLUDE_DIRS)
