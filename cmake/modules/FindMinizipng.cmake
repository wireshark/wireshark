#
# - Find minizip-ng libraries
#
#  MINIZIPNG_INCLUDE_DIRS - where to find minizip-ng headers.
#  MINIZIPNG_LIBRARIES    - List of libraries when using minizip-ng.
#  MINIZIPNG_FOUND        - True if minizip-ng is found.
#  MINIZIPNG_DLL_DIR      - (Windows) Path to the minizip-ng DLL.
#  MINIZIPNG_DLLS         - (Windows) Name of the minizip-ng DLL.

FindWSWinLibs("minizip-ng" "MINIZIPNG_HINTS")

if(NOT USE_REPOSITORY)
  find_package(PkgConfig QUIET)
  pkg_search_module(MINIZIPNG QUIET minizip-ng)
endif()

find_path(MINIZIPNG_INCLUDE_DIR
  NAMES
    mz_compat.h
    minizip-ng/mz_compat.h
  HINTS
    ${MINIZIPNG_INCLUDE_DIRS}
    "${MINIZIPNG_HINTS}/include"
)

get_filename_component(MINIZIPNG_PARENT_DIR ${MINIZIPNG_INCLUDE_DIR} DIRECTORY)
if(EXISTS "${MINIZIPNG_PARENT_DIR}/minizip-ng/mz_compat.h")
  set(MINIZIPNG_INCLUDE_DIR "${MINIZIPNG_PARENT_DIR}")
endif()

find_library(MINIZIPNG_LIBRARY
  NAMES
    libminizip-ng minizip-ng
  HINTS
    ${MINIZIPNG_LIBRARY_DIRS}
    ${MINIZIPNG_HINTS}/lib
  PATH
    /opt
    /opt/homebrew/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Minizipng
  REQUIRED_VARS   MINIZIPNG_LIBRARY MINIZIPNG_INCLUDE_DIR
  VERSION_VAR     MINIZIPNG_VERSION)

if(MINIZIPNG_FOUND)
  set(MINIZIPNG_LIBRARIES ${MINIZIPNG_LIBRARY})

  find_library(BZ2_LIBRARY
    NAMES
      bz2
    HINTS
      ${MINIZIPNG_LIBRARY_DIRS}
      "${MINIZIPNG_HINTS}/lib"
  )
  list(APPEND MINIZIPNG_LIBRARIES ${BZ2_LIBRARY})

  find_library(LZMA_LIBRARY
    NAMES
      lzma
    HINTS
      ${MINIZIPNG_LIBRARY_DIRS}
      "${MINIZIPNG_HINTS}/lib"
  )
  list(APPEND MINIZIPNG_LIBRARIES ${LZMA_LIBRARY})

  find_library(ZSTD_LIBRARY
    NAMES
      zstd
    HINTS
      ${MINIZIPNG_LIBRARY_DIRS}
      "${MINIZIPNG_HINTS}/lib"
  )
  list(APPEND MINIZIPNG_LIBRARIES ${ZSTD_LIBRARY})

  if(WIN32)
    find_library(Bcrypt_LIBRARY
      NAMES
        Bcrypt
    )

    list(APPEND MINIZIPNG_LIBRARIES ${Bcrypt_LIBRARY})
  endif()

  # do we need openssl on *nix*

  # message(STATUS "Minizip-ng, MINIZIPNG_LIBRARIES ${MINIZIPNG_LIBRARIES}")

  set(MINIZIPNG_INCLUDE_DIRS ${MINIZIPNG_INCLUDE_DIR})
  set(HAVE_MINIZIPNG ON)

  # Some distributions have minizip-ng code instead of the original zlib contrib
  # library but keep the old minizip name (because minizip-ng is
  # better maintained and provides a compatibility layer). However the
  # minizip-ng compatibility layer has some issues. We need to check
  # for renamed struct members to avoid an endless game of whack-a-mole.
  include(CheckStructHasMember)
  check_struct_has_member("zip_fileinfo" "dos_date" "minizip-ng/zip.h" HAVE_MZCOMPAT_DOS_DATE)

  if(WIN32)
    set(MINIZIPNG_DLL_DIR "${MINIZIPNG_HINTS}/bin"
      CACHE PATH "Path to Minizip DLL"
    )

    AddWSWinDLLS(MINIZIPNG MINIZIPNG_HINTS "bz2*" "zstd*")

    mark_as_advanced(MINIZIPNG_DLL_DIR MINIZIPNG_DLLS MINIZIPNG_PDBS)
  endif()
else()
  set(MINIZIPNG_LIBRARIES)
  set(MINIZIPNG_INCLUDE_DIRS)
  set(MINIZIPNG_DLL_DIR)
  set(MINIZIPNG_DLLS)
endif()

mark_as_advanced(MINIZIPNG_LIBRARIES MINIZIPNG_INCLUDE_DIRS)
