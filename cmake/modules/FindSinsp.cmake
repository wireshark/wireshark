#
# - Find libsinsp
# Find libsinsp and libscap includes and libraries
# Adapted from FindZSTD.cmake.
#
#  SINSP_INCLUDE_DIRS - where to find sinsp.h, scap.h, etc.
#  SINSP_LIBRARIES    - List of libraries when using libsinsp.
#  SINSP_FOUND        - True if libsinsp found.
#  SINSP_DLL_DIR      - (Windows) Path to the libsinsp and libscap DLLs
#  SINSP_DLL          - (Windows) Name of the libsinsp and libscap DLLs

include( FindWSWinLibs )
FindWSWinLibs( "libsinsp-.*" "SINSP_HINTS" )

if( NOT WIN32)
  find_package(PkgConfig)
  pkg_search_module(Sinsp libsinsp)
endif()

find_path(SINSP_INCLUDE_DIR
  NAMES sinsp.h
  HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
  PATH_SUFFIXES userspace/libsinsp
  /usr/include
  /usr/local/include
)

find_path(SCAP_INCLUDE_DIR
  NAMES scap.h
  HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
  PATH_SUFFIXES userspace/libscap
  /usr/include
  /usr/local/include
)

find_library(SINSP_LIBRARY
  NAMES sinsp
  HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib"
  PATH_SUFFIXES libsinsp
  PATHS
  /usr/lib
  /usr/local/lib
)

find_library(SCAP_LIBRARY
  NAMES scap
  HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib"
  PATH_SUFFIXES libscap
  PATHS
  /usr/lib
  /usr/local/lib
)

find_path(JSON_INCLUDE_DIR
  NAMES json/json.h
  HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
  /usr/include
  /usr/local/include
)

find_library(JSONCPP_LIBRARY
  NAMES jsoncpp
  HINTS "${SINSP_LIBDIR}" "${SCAP_HINTS}/lib"
  PATHS
  /usr/lib
  /usr/local/lib
)

find_path(TBB_INCLUDE_DIR
  NAMES tbb/tbb.h
  HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
  /usr/include
  /usr/local/include
)

find_library(TBB_LIBRARY
  NAMES tbb
  HINTS "${SINSP_LIBDIR}" "${SCAP_HINTS}/lib"
  PATHS
  /usr/lib
  /usr/local/lib
)

# if( SINSP_INCLUDE_DIR AND SCAP_INCLUDE_DIR AND SINSP_LIBRARY AND SCAP_LIBRARY )
#   file(STRINGS ${SINSP_INCLUDE_DIR}/sinsp.h SINSP_VERSION_MAJOR
#     REGEX "#define[ ]+SINSP_VERSION_MAJOR[ ]+[0-9]+")
#   string(REGEX MATCH "[0-9]+" SINSP_VERSION_MAJOR ${SINSP_VERSION_MAJOR})
#   file(STRINGS ${SINSP_INCLUDE_DIR}/sinsp.h SINSP_VERSION_MINOR
#     REGEX "#define[ ]+SINSP_VERSION_MINOR[ ]+[0-9]+")
#   string(REGEX MATCH "[0-9]+" SINSP_VERSION_MINOR ${SINSP_VERSION_MINOR})
#   file(STRINGS ${SINSP_INCLUDE_DIR}/sinsp.h SINSP_VERSION_RELEASE
#     REGEX "#define[ ]+SINSP_VERSION_RELEASE[ ]+[0-9]+")
#   string(REGEX MATCH "[0-9]+" SINSP_VERSION_RELEASE ${SINSP_VERSION_RELEASE})
#   set(SINSP_VERSION ${SINSP_VERSION_MAJOR}.${SINSP_VERSION_MINOR}.${SINSP_VERSION_RELEASE})
# endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sinsp
    REQUIRED_VARS
        SINSP_LIBRARY SINSP_INCLUDE_DIR
	SCAP_LIBRARY SCAP_INCLUDE_DIR
	JSONCPP_LIBRARY JSON_INCLUDE_DIR
	TBB_LIBRARY TBB_INCLUDE_DIR
#     VERSION_VAR     SINSP_VERSION
)

if( SINSP_FOUND )
  set( SINSP_INCLUDE_DIRS ${SINSP_INCLUDE_DIR} ${SCAP_INCLUDE_DIR} ${JSON_INCLUDE_DIR} ${TBB_INCLUDE_DIR} )
  set( SINSP_LIBRARIES ${SINSP_LIBRARY} ${SCAP_LIBRARY} ${JSONCPP_LIBRARY} ${TBB_LIBRARY} )
#   if (WIN32)
#     set ( SINSP_DLL_DIR "${SINSP_HINTS}/bin"
#       CACHE PATH "Path to sinsp DLL"
#     )
#     file( GLOB _SINSP_dll RELATIVE "${SINSP_DLL_DIR}"
#       "${SINSP_DLL_DIR}/sinsp*.dll"
#     )
#     set ( SINSP_DLL ${_SINSP_dll}
#       # We're storing filenames only. Should we use STRING instead?
#       CACHE FILEPATH "sinsp DLL file name"
#     )
#     mark_as_advanced( SINSP_DLL_DIR SINSP_DLL )
#   endif()
else()
  set( SINSP_INCLUDE_DIRS )
  set( SINSP_LIBRARIES )
endif()

mark_as_advanced( SINSP_LIBRARIES SINSP_INCLUDE_DIRS )
