#
# - Find WinSparkle
# Find the native WinSparkle includes and library
#
#  WINSPARKLE_INCLUDE_DIRS - where to find WinSparkle.h, etc.
#  WINSPARKLE_LIBRARIES    - List of libraries when using WinSparkle.
#  WINSPARKLE_FOUND        - True if WinSparkle found.
#  WINSPARKLE_DLL_DIR      - (Windows) Path to the WinSparkle DLL.
#  WINSPARKLE_DLL          - (Windows) Name of the WinSparkle DLL.


if (WINSPARKLE_INCLUDE_DIRS)
  # Already in cache, be silent
  set(WINSPARKLE_FIND_QUIETLY TRUE)
endif()

include(FindWSWinLibs)
FindWSWinLibs("WinSparkle-.*" WINSPARKLE_HINTS)

find_path(WINSPARKLE_INCLUDE_DIR
  NAMES winsparkle.h
  HINTS "${WINSPARKLE_HINTS}/include"
)

find_library(WINSPARKLE_LIBRARY
  NAMES WinSparkle
  HINTS "${WINSPARKLE_HINTS}/lib"
)

# WinSparkle uses the "WIN_SPARKLE_" variable prefix. We probably should too.
if( WINSPARKLE_INCLUDE_DIR AND WINSPARKLE_LIBRARY )
  file(STRINGS ${WINSPARKLE_INCLUDE_DIR}/winsparkle-version.h WIN_SPARKLE_VERSION_MAJOR
    REGEX "#define[ \t]+WIN_SPARKLE_VERSION_MAJOR[ \t]+[0-9]+")
  string(REGEX MATCH "[0-9]+" WIN_SPARKLE_VERSION_MAJOR ${WIN_SPARKLE_VERSION_MAJOR})
  file(STRINGS ${WINSPARKLE_INCLUDE_DIR}/winsparkle-version.h WIN_SPARKLE_VERSION_MINOR
    REGEX "#define[ \t]+WIN_SPARKLE_VERSION_MINOR[ \t]+[0-9]+")
  string(REGEX MATCH "[0-9]+" WIN_SPARKLE_VERSION_MINOR ${WIN_SPARKLE_VERSION_MINOR})
  file(STRINGS ${WINSPARKLE_INCLUDE_DIR}/winsparkle-version.h WIN_SPARKLE_VERSION_MICRO
    REGEX "#define[ \t]+WIN_SPARKLE_VERSION_MICRO[ \t]+[0-9]+")
  string(REGEX MATCH "[0-9]+" WIN_SPARKLE_VERSION_MICRO ${WIN_SPARKLE_VERSION_MICRO})
  set(WINSPARKLE_VERSION ${WIN_SPARKLE_VERSION_MAJOR}.${WIN_SPARKLE_VERSION_MINOR}.${WIN_SPARKLE_VERSION_MICRO})
endif()

# Handle the QUIETLY and REQUIRED arguments and set WINSPARKLE_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WinSparkle
  REQUIRED_VARS WINSPARKLE_LIBRARY WINSPARKLE_INCLUDE_DIR
  VERSION_VAR WINSPARKLE_VERSION
)

if(WINSPARKLE_FOUND)
  set(WINSPARKLE_LIBRARIES ${WINSPARKLE_LIBRARY} )
  set(WINSPARKLE_INCLUDE_DIRS ${WINSPARKLE_INCLUDE_DIR} )
  if (WIN32)
    set (WINSPARKLE_DLL_DIR "${WINSPARKLE_HINTS}/bin"
      CACHE PATH "Path to the WinSparkle DLL"
    )
    set (WINSPARKLE_DLL WinSparkle.dll
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "WinSparkle DLL file name"
    )
    mark_as_advanced( WINSPARKLE_DLL_DIR WINSPARKLE_DLL )
  endif()
else()
  set(WINSPARKLE_LIBRARIES )
  set(WINSPARKLE_INCLUDE_DIRS )
  set(WINSPARKLE_DLL_DIR )
  set(WINSPARKLE_DLL )
endif()

mark_as_advanced( WINSPARKLE_LIBRARIES WINSPARKLE_INCLUDE_DIRS )
