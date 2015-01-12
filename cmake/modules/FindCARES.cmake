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

FIND_PATH(CARES_INCLUDE_DIR ares.h HINTS "${CARES_HINTS}/include" )

SET(CARES_NAMES cares libcares-2)
FIND_LIBRARY(CARES_LIBRARY NAMES ${CARES_NAMES} HINTS "${CARES_HINTS}/lib" )

# handle the QUIETLY and REQUIRED arguments and set CARES_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CARES DEFAULT_MSG CARES_LIBRARY CARES_INCLUDE_DIR)

IF(CARES_FOUND)
  SET( CARES_LIBRARIES ${CARES_LIBRARY} )
  SET( CARES_INCLUDE_DIRS ${CARES_INCLUDE_DIR} )
  if (WIN32)
    set ( CARES_DLL_DIR "${CARES_HINTS}/bin"
      CACHE PATH "Path to C-Ares DLL"
    )
    file( GLOB _cares_dll RELATIVE "${CARES_DLL_DIR}"
      "${CARES_DLL_DIR}/libcares-*.dll"
    )
    set ( CARES_DLL ${_cares_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "C-Ares DLL file name"
    )
    mark_as_advanced( CARES_DLL_DIR CARES_DLL )
  endif()
ELSE(CARES_FOUND)
  SET( CARES_LIBRARIES )
  SET( CARES_INCLUDE_DIRS )
  SET( CARES_DLL_DIR )
  SET( CARES_DLL )
ENDIF(CARES_FOUND)

MARK_AS_ADVANCED( CARES_LIBRARIES CARES_INCLUDE_DIRS )
