#
# - Find minizip libraries
#
#  MINIZIP_INCLUDE_DIRS - where to find minizip headers.
#  MINIZIP_LIBRARIES    - List of libraries when using minizip.
#  MINIZIP_FOUND        - True if minizip is found.
#  MINIZIP_DLL_DIR      - (Windows) Path to the minizip DLL.
#  MINIZIP_DLL          - (Windows) Name of the minizip DLL.

FindWSWinLibs("minizip-[0-9]" "MINIZIP_HINTS")

if(NOT USE_REPOSITORY)
  find_package(PkgConfig QUIET)
  pkg_search_module(MINIZIP QUIET minizip)
endif()

find_path(MINIZIP_INCLUDE_DIR
  NAMES
    unzip.h
    minizip/unzip.h
  HINTS
    ${MINIZIP_INCLUDE_DIRS}
    "${MINIZIP_HINTS}/include"
)

get_filename_component(MINIZIP_PARENT_DIR ${MINIZIP_INCLUDE_DIR} DIRECTORY)
if(EXISTS "${MINIZIP_PARENT_DIR}/minizip/unzip.h")
  set(MINIZIP_INCLUDE_DIR "${MINIZIP_PARENT_DIR}")
endif()

find_library(MINIZIP_LIBRARY
  NAMES
    minizip
  HINTS
    ${MINIZIP_LIBRARY_DIRS}
    "${MINIZIP_HINTS}/lib"
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Minizip
  REQUIRED_VARS   MINIZIP_LIBRARY MINIZIP_INCLUDE_DIR
  VERSION_VAR     MINIZIP_VERSION)

if(MINIZIP_FOUND)
  set(MINIZIP_LIBRARIES ${MINIZIP_LIBRARY})
  set(MINIZIP_INCLUDE_DIRS ${MINIZIP_INCLUDE_DIR})
  set(HAVE_MINIZIP ON)

  # Some distributions have minizip-ng code instead of the original zlib contrib
  # library but keep the old minizip name (because minizip-ng is
  # better maintained and provides a compatibility layer). However the
  # minizip-ng compatibility layer has some issues. We need to check
  # for renamed struct members to avoid an endless game of whack-a-mole.
  include(CheckStructHasMember)
  check_struct_has_member("zip_fileinfo" "dos_date" "minizip/zip.h" HAVE_MZCOMPAT_DOS_DATE)

  if(WIN32)
    set(MINIZIP_DLL_DIR "${MINIZIP_HINTS}/bin"
      CACHE PATH "Path to Minizip DLL"
    )
    file(GLOB _minizip_dll RELATIVE "${MINIZIP_DLL_DIR}"
      "${MINIZIP_DLL_DIR}/minizip.dll"
    )
    set(MINIZIP_DLL ${_minizip_dll}
      CACHE FILEPATH "Minizip DLL file name"
    )
    file(GLOB _minizip_pdb RELATIVE "${MINIZIP_DLL_DIR}"
      "${MINIZIP_DLL_DIR}/minizip.pdb"
    )
    set(MINIZIP_PDB ${_minizip_pdb}
      CACHE FILEPATH "Minizip PDB file name"
    )
    mark_as_advanced(MINIZIP_DLL_DIR MINIZIP_DLL MINIZIP_PDB)
  endif()
else()
  set(MINIZIP_LIBRARIES)
  set(MINIZIP_INCLUDE_DIRS)
  set(MINIZIP_DLL_DIR)
  set(MINIZIP_DLL)
endif()

mark_as_advanced(MINIZIP_LIBRARIES MINIZIP_INCLUDE_DIRS)

