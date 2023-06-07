#
# - Find WinSparkle
# Find the native WinSparkle includes and library
#
#  WINSPARKLE_INCLUDE_DIRS - where to find WinSparkle.h, etc.
#  WINSPARKLE_LIBRARIES    - List of libraries when using WinSparkle.
#  WINSPARKLE_FOUND        - True if WinSparkle found.
#  WINSPARKLE_DLL_DIR      - (Windows) Path to the WinSparkle DLL.
#  WINSPARKLE_DLL          - (Windows) Name of the WinSparkle DLL.


IF (WINSPARKLE_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(WINSPARKLE_FIND_QUIETLY TRUE)
ENDIF (WINSPARKLE_INCLUDE_DIRS)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("WinSparkle.*" "WINSPARKLE_HINTS")

set (_release_subdir "${WIRESHARK_TARGET_PLATFORM}/Release")

FIND_PATH(WINSPARKLE_INCLUDE_DIR winsparkle.h HINTS "${WINSPARKLE_HINTS}/include" )

FIND_LIBRARY(WINSPARKLE_LIBRARY NAMES WinSparkle HINTS "${WINSPARKLE_HINTS}/${_release_subdir}" )

# handle the QUIETLY and REQUIRED arguments and set WINSPARKLE_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(WinSparkle DEFAULT_MSG WINSPARKLE_LIBRARY WINSPARKLE_INCLUDE_DIR)

IF(WINSPARKLE_FOUND)
  SET(WINSPARKLE_LIBRARIES ${WINSPARKLE_LIBRARY} )
  SET(WINSPARKLE_INCLUDE_DIRS ${WINSPARKLE_INCLUDE_DIR} )
  if (WIN32)
    set (WINSPARKLE_DLL_DIR "${WINSPARKLE_HINTS}/${_release_subdir}"
      CACHE PATH "Path to the WinSparkle DLL"
    )
    file( GLOB _winsparkle_dll RELATIVE "${WINSPARKLE_DLL_DIR}"
      "${WINSPARKLE_DLL_DIR}/WinSparkle.dll"
    )
    set ( WINSPARKLE_DLL ${_winsparkle_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "WinSparkle DLL file name"
    )
    mark_as_advanced( WINSPARKLE_DLL_DIR WINSPARKLE_DLL )
  endif()
ELSE(WINSPARKLE_FOUND)
  SET(WINSPARKLE_LIBRARIES )
  SET(WINSPARKLE_INCLUDE_DIRS )
  SET(WINSPARKLE_DLL_DIR )
  SET(WINSPARKLE_DLL )
ENDIF(WINSPARKLE_FOUND)

unset(_release_subdir)

MARK_AS_ADVANCED( WINSPARKLE_LIBRARIES WINSPARKLE_INCLUDE_DIRS )
