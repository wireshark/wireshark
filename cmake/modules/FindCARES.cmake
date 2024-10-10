#
# - Find cares
# Find the native CARES includes and library
#
#  CARES_INCLUDE_DIRS - where to find cares.h, etc.
#  CARES_LIBRARIES    - List of libraries when using cares.
#  CARES_FOUND        - True if cares found.
#  CARES_DLL_DIR      - (Windows) Path to the c-ares DLL.
#  CARES_DLL          - (Windows) Name of the c-ares DLL.


IF (CARES_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(CARES_FIND_QUIETLY TRUE)
ENDIF (CARES_INCLUDE_DIRS)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("c-ares-.*" "CARES_HINTS")

find_path( CARES_INCLUDE_DIR
  NAMES ares.h
  PATH_SUFFIXES
        include
  HINTS
    "${CARES_INCLUDEDIR}"
    "${CARES_HINTS}"
)

find_library( CARES_LIBRARY
  NAMES cares libcares-2
  PATH_SUFFIXES
        lib64 lib
  HINTS
    "${CARES_LIBDIR}"
    "${CARES_HINTS}"
)

# Try to retrieve version from header if found
# Adapted from https://stackoverflow.com/a/47084079/82195
if(CARES_INCLUDE_DIR)
  file(READ "${CARES_INCLUDE_DIR}/ares_version.h" _ares_version_h)

  string(REGEX MATCH "#[\t ]*define[ \t]+ARES_VERSION_MAJOR[ \t]+([0-9]+)" _ ${_ares_version_h})
  set(_ares_version_major ${CMAKE_MATCH_1})
  string(REGEX MATCH "#[\t ]*define[ \t]+ARES_VERSION_MINOR[ \t]+([0-9]+)" _ ${_ares_version_h})
  set(_ares_version_minor ${CMAKE_MATCH_1})
  string(REGEX MATCH "#[\t ]*define[ \t]+ARES_VERSION_PATCH[ \t]+([0-9]+)" _ ${_ares_version_h})
  set(_ares_version_patch ${CMAKE_MATCH_1})
  set(CARES_VERSION ${_ares_version_major}.${_ares_version_minor}.${_ares_version_patch})

  unset(_ares_version_h)
  unset(_ares_version_major)
  unset(_ares_version_minor)
  unset(_ares_version_patch)
endif()

# handle the QUIETLY and REQUIRED arguments and set CARES_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CARES
    REQUIRED_VARS   CARES_LIBRARY CARES_INCLUDE_DIR
    VERSION_VAR     CARES_VERSION)

IF(CARES_FOUND)
  SET( CARES_LIBRARIES ${CARES_LIBRARY} )
  SET( CARES_INCLUDE_DIRS ${CARES_INCLUDE_DIR} )
  if (WIN32)
    set ( CARES_DLL_DIR "${CARES_HINTS}/bin"
      CACHE PATH "Path to C-Ares DLL"
    )
    file( GLOB _cares_dll RELATIVE "${CARES_DLL_DIR}"
      "${CARES_DLL_DIR}/cares.dll"
    )
    set ( CARES_DLL ${_cares_dll}
      CACHE FILEPATH "C-Ares DLL file name"
    )
    file( GLOB _cares_pdb RELATIVE "${CARES_DLL_DIR}"
      "${CARES_DLL_DIR}/cares.pdb"
    )
    set ( CARES_PDB ${_cares_pdb}
      CACHE FILEPATH "C-Ares PDB file name"
    )
    mark_as_advanced( CARES_DLL_DIR CARES_DLL CARES_PDB )
  endif()
ELSE(CARES_FOUND)
  SET( CARES_LIBRARIES )
  SET( CARES_INCLUDE_DIRS )
  SET( CARES_DLL_DIR )
  SET( CARES_DLL )
ENDIF(CARES_FOUND)

MARK_AS_ADVANCED( CARES_LIBRARIES CARES_INCLUDE_DIRS )
