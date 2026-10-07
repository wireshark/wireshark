#
# - Find PackageKit GLib libraries
#
#  PACKAGEKIT_INCLUDE_DIRS - where to find packagekit-glib2/packagekit.h, etc.
#  PACKAGEKIT_LIBRARIES    - List of libraries when using packagekit-glib2.
#  PACKAGEKIT_FOUND        - True if packagekit-glib2 is found.
#  PACKAGEKIT_VERSION      - The packagekit-glib2 version.
#  PACKAGEKIT_REQUIRES_API_ACK - True for 1.1.x, see cmakeconfig.h.in.

find_package(PkgConfig QUIET)
pkg_search_module(PC_PACKAGEKIT QUIET packagekit-glib2)

find_path(PACKAGEKIT_INCLUDE_DIR
  NAMES
    packagekit-glib2/packagekit.h
  HINTS
    ${PC_PACKAGEKIT_INCLUDE_DIRS}
  PATH_SUFFIXES
    packagekit
    PackageKit
)

find_library(PACKAGEKIT_LIBRARY
  NAMES
    packagekit-glib2
  HINTS
    ${PC_PACKAGEKIT_LIBRARY_DIRS}
)

# Without pkg-config, read the version from the generated header
set(PACKAGEKIT_VERSION ${PC_PACKAGEKIT_VERSION})
if(NOT PACKAGEKIT_VERSION AND PACKAGEKIT_INCLUDE_DIR AND EXISTS "${PACKAGEKIT_INCLUDE_DIR}/packagekit-glib2/pk-version.h")
  file(STRINGS "${PACKAGEKIT_INCLUDE_DIR}/packagekit-glib2/pk-version.h" PK_VERSION_H REGEX "^#define PK_M[A-Z]+_VERSION[ \t]+\\([0-9]+\\)")
  string(REGEX REPLACE ".*PK_MAJOR_VERSION[ \t]+\\(([0-9]+)\\).*" "\\1" PK_MAJOR "${PK_VERSION_H}")
  string(REGEX REPLACE ".*PK_MINOR_VERSION[ \t]+\\(([0-9]+)\\).*" "\\1" PK_MINOR "${PK_VERSION_H}")
  string(REGEX REPLACE ".*PK_MICRO_VERSION[ \t]+\\(([0-9]+)\\).*" "\\1" PK_MICRO "${PK_VERSION_H}")
  set(PACKAGEKIT_VERSION "${PK_MAJOR}.${PK_MINOR}.${PK_MICRO}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PACKAGEKIT
  REQUIRED_VARS   PACKAGEKIT_LIBRARY PACKAGEKIT_INCLUDE_DIR
  VERSION_VAR     PACKAGEKIT_VERSION)

set(PACKAGEKIT_REQUIRES_API_ACK)
if(PACKAGEKIT_FOUND AND PACKAGEKIT_VERSION VERSION_LESS "1.2.0")
  set(PACKAGEKIT_REQUIRES_API_ACK 1)
endif()

if(PACKAGEKIT_FOUND)
  set(PACKAGEKIT_LIBRARIES ${PACKAGEKIT_LIBRARY})
  set(PACKAGEKIT_INCLUDE_DIRS ${PACKAGEKIT_INCLUDE_DIR})
else()
  set(PACKAGEKIT_LIBRARIES)
  set(PACKAGEKIT_INCLUDE_DIRS)
endif()

mark_as_advanced(PACKAGEKIT_LIBRARIES PACKAGEKIT_INCLUDE_DIRS)
