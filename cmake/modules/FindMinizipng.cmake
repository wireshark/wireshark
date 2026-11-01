#
# - Find minizip-ng library, only if it has the compatibility layer with
#   the original minizip
#
#  MINIZIPNG_INCLUDE_DIRS - where to find minizip-ng headers.
#  MINIZIPNG_LIBRARIES    - List of libraries when using minizip-ng.
#  MINIZIPNG_FOUND        - True if minizip-ng is found.
#
# Creates an IMPORTED target Minizipng::Minizipng if found

include(FindWSWinLibs)
FindWSWinLibs("minizip-ng" "MINIZIPNG_HINTS")

if(NOT USE_REPOSITORY)
  find_package(PkgConfig QUIET)
  pkg_search_module(MINIZIPNG QUIET minizip-ng)
else()
  # FindWSLibrary caches <NAME>_LIBRARY_RELEASE and <NAME>_LIBRARY_DEBUG.
  # Remove the cache entries that find_library() created before, which
  # always used the release libraries.
  unset(MINIZIPNG_LIBRARY CACHE)
endif()
# We used to find these with names that other Find modules might use.
unset(BZ2_LIBRARY CACHE)
unset(LZMA_LIBRARY CACHE)

find_path(MINIZIPNG_INCLUDE_DIR
  NAMES
    unzip.h
    minizip-ng/unzip.h
  HINTS
    ${MINIZIPNG_INCLUDE_DIRS}
    "${MINIZIPNG_HINTS}/include"
)

get_filename_component(MINIZIPNG_PARENT_DIR ${MINIZIPNG_INCLUDE_DIR} DIRECTORY)
if(EXISTS "${MINIZIPNG_PARENT_DIR}/minizip-ng/unzip.h")
  set(MINIZIPNG_INCLUDE_DIR "${MINIZIPNG_PARENT_DIR}")
endif()

include(FindWSLibrary)
FindWSLibrary(MINIZIPNG_LIBRARY
  NAMES
    libminizip-ng minizip-ng
  HINTS
    ${MINIZIPNG_LIBRARY_DIRS}
  PATHS
    /opt
    /opt/homebrew/lib
  WIN32_HINTS
    ${MINIZIPNG_HINTS}
)

if(EXISTS "${MINIZIPNG_INCLUDE_DIR}/minizip-ng/mz.h")
  set(_version_regex "^#define[ \t]+MZ_VERSION[ \t(]+\"([^\"]+)\".*")
  file(STRINGS "${MINIZIPNG_INCLUDE_DIR}/minizip-ng/mz.h" MINIZIPNG_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1" MINIZIPNG_VERSION "${MINIZIPNG_VERSION}")
  unset(_version_regex)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Minizipng
  REQUIRED_VARS   MINIZIPNG_LIBRARY MINIZIPNG_INCLUDE_DIR
  VERSION_VAR     MINIZIPNG_VERSION)

if(MINIZIPNG_FOUND)
  set(MINIZIPNG_INCLUDE_DIRS ${MINIZIPNG_INCLUDE_DIR})
  set(HAVE_MINIZIPNG ON)

  # Our minizip-ng from vcpkg is a static library, so we need to link the
  # compression libraries that it uses. bz2 and liblzma are only in the
  # minizip-ng package, which also has zlib and zstd. Use our own zlib
  # and zstd if we have them, so that only one copy of each is loaded.
  set(_minizipng_link_libraries)

  FindWSLibrary(MINIZIPNG_BZ2_LIBRARY
    NAMES bz2 bz2d
    HINTS ${MINIZIPNG_LIBRARY_DIRS}
    WIN32_HINTS ${MINIZIPNG_HINTS}
  )
  if(MINIZIPNG_BZ2_LIBRARY)
    ws_add_imported_library(Minizipng::BZip2 MINIZIPNG_BZ2_LIBRARY DLL "bz2*")
    list(APPEND _minizipng_link_libraries Minizipng::BZip2)
  endif()

  FindWSLibrary(MINIZIPNG_LZMA_LIBRARY
    NAMES lzma
    HINTS ${MINIZIPNG_LIBRARY_DIRS}
    WIN32_HINTS ${MINIZIPNG_HINTS}
  )
  if(MINIZIPNG_LZMA_LIBRARY)
    ws_add_imported_library(Minizipng::LZMA MINIZIPNG_LZMA_LIBRARY DLL "liblzma*")
    list(APPEND _minizipng_link_libraries Minizipng::LZMA)
  endif()

  if(TARGET ZSTD::ZSTD)
    list(APPEND _minizipng_link_libraries ZSTD::ZSTD)
  else()
    FindWSLibrary(MINIZIPNG_ZSTD_LIBRARY
      NAMES zstd
      HINTS ${MINIZIPNG_LIBRARY_DIRS}
      WIN32_HINTS ${MINIZIPNG_HINTS}
    )
    if(MINIZIPNG_ZSTD_LIBRARY)
      ws_add_imported_library(Minizipng::ZSTD MINIZIPNG_ZSTD_LIBRARY DLL "zstd*")
      list(APPEND _minizipng_link_libraries Minizipng::ZSTD)
    endif()
  endif()

  if(TARGET ZLIB::ZLIB)
    list(APPEND _minizipng_link_libraries ZLIB::ZLIB)
  endif()

  if(WIN32)
    list(APPEND _minizipng_link_libraries bcrypt)
  endif()

  # do we need openssl on *nix*

  ws_add_imported_library(Minizipng::Minizipng MINIZIPNG_LIBRARY
    INCLUDE_DIRS ${MINIZIPNG_INCLUDE_DIRS}
    LINK_LIBRARIES ${_minizipng_link_libraries}
  )
  unset(_minizipng_link_libraries)
  set(MINIZIPNG_LIBRARIES Minizipng::Minizipng)

  # Some distributions have minizip-ng code instead of the original zlib contrib
  # library but keep the old minizip name (because minizip-ng is
  # better maintained and provides a compatibility layer). However the
  # minizip-ng compatibility layer has some issues. We need to check
  # for renamed struct members to avoid an endless game of whack-a-mole.
  include(CheckStructHasMember)
  ws_reset_checks_on_change(HAVE_MZCOMPAT_DOS_DATE "${MINIZIPNG_INCLUDE_DIR}" HAVE_MZCOMPAT_DOS_DATE)
  check_struct_has_member("zip_fileinfo" "dos_date" "minizip-ng/zip.h" HAVE_MZCOMPAT_DOS_DATE)
else()
  set(MINIZIPNG_LIBRARIES)
  set(MINIZIPNG_INCLUDE_DIRS)
endif()

mark_as_advanced(MINIZIPNG_LIBRARIES MINIZIPNG_INCLUDE_DIRS)
