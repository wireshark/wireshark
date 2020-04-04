#
# - Find minizip libraries
#
#  MINIZIP_INCLUDE_DIRS - where to find minizip headers.
#  MINIZIP_LIBRARIES    - List of libraries when using minizip.
#  MINIZIP_FOUND        - True if minizip is found.

FindWSWinLibs( "minizip-*" "MINIZIP_HINTS" )

if(NOT WIN32)
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
  SET(HAVE_MINIZIP ON)
else()
  set(MINIZIP_LIBRARIES)
  set(MINIZIP_INCLUDE_DIRS)
endif()

mark_as_advanced(MINIZIP_LIBRARIES MINIZIP_INCLUDE_DIRS)

