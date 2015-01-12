#
# - Find GeoIP
# Find the native GEOIP includes and library
#
#  GEOIP_INCLUDE_DIRS - where to find GeoIP.h, etc.
#  GEOIP_LIBRARIES    - List of libraries when using GeoIP.
#  GEOIP_FOUND        - True if GeoIP found.
#  GEOIP_DLL_DIR      - (Windows) Path to the GeoIP DLL.
#  GEOIP_DLL          - (Windows) Name of the GeoIP DLL.


IF (GEOIP_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(GEOIP_FIND_QUIETLY TRUE)
ENDIF (GEOIP_INCLUDE_DIRS)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("GeoIP-.*" "GEOIP_HINTS")

find_package(PkgConfig)
pkg_search_module(GEOIP geoip)

FIND_PATH(GEOIP_INCLUDE_DIR GeoIP.h
  HINTS
    "${GEOIP_INCLUDEDIR}"
    "${GEOIP_HINTS}/include"
)

SET(GEOIP_NAMES GeoIP libGeoIP-1)
FIND_LIBRARY(GEOIP_LIBRARY NAMES ${GEOIP_NAMES}
  HINTS
    "${GEOIP_LIBDIR}"
    "${GEOIP_HINTS}/lib"
  )

# handle the QUIETLY and REQUIRED arguments and set GEOIP_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GEOIP DEFAULT_MSG GEOIP_LIBRARY GEOIP_INCLUDE_DIR)

IF(GEOIP_FOUND)
  SET(GEOIP_LIBRARIES ${GEOIP_LIBRARY} )
  SET(GEOIP_INCLUDE_DIRS ${GEOIP_INCLUDE_DIR} )
  INCLUDE(CheckFunctionExists)
  SET(CMAKE_REQUIRED_INCLUDES ${GEOIP_INCLUDE_DIRS})
  SET(CMAKE_REQUIRED_LIBRARIES ${GEOIP_LIBRARIES})
  CHECK_FUNCTION_EXISTS("GeoIP_country_name_by_ipnum_v6" HAVE_GEOIP_V6)
  SET(CMAKE_REQUIRED_INCLUDES "")
  SET(CMAKE_REQUIRED_LIBRARIES "")
  if (WIN32)
    set ( GEOIP_DLL_DIR "${GEOIP_HINTS}/bin"
      CACHE PATH "Path to the GeoIP DLL"
    )
    file( GLOB _geoip_dll RELATIVE "${GEOIP_DLL_DIR}"
      "${GEOIP_DLL_DIR}/libGeoIP-*.dll"
    )
    set ( GEOIP_DLL ${_geoip_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "GeoIP DLL file name"
    )
    mark_as_advanced( GEOIP_DLL_DIR GEOIP_DLL )
  endif()
ELSE(GEOIP_FOUND)
  SET(GEOIP_LIBRARIES )
  SET(GEOIP_INCLUDE_DIRS )
  SET(GEOIP_DLL_DIR )
  SET(GEOIP_DLL )
ENDIF(GEOIP_FOUND)

MARK_AS_ADVANCED( GEOIP_LIBRARIES GEOIP_INCLUDE_DIRS )
