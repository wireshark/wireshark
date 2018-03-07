#
# - Try to find libmaxminddb.
# Once done this will define
#  MAXMINDDB_FOUND - System has libmaxminddb
#  MAXMINDDB_INCLUDE_DIRS - The libmaxminddb include directories
#  MAXMINDDB_LIBRARIES - The libraries needed to use libmaxminddb
#  MAXMINDDB_DEFINITIONS - Compiler switches required for using libmaxminddb
#  MAXMINDDB_DLL_DIR      - (Windows) Path to the MaxMindDB DLL.
#  MAXMINDDB_DLL          - (Windows) Name of the MaxMindDB DLL.

IF (MAXMINDDB_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(MAXMINDDB_FIND_QUIETLY TRUE)
ENDIF (MAXMINDDB_INCLUDE_DIRS)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("MaxMindDB-.*" "MAXMINDDB_HINTS")

IF (NOT WIN32)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBMAXMINDDB QUIET libmaxminddb)
  set(MAXMINDDB_DEFINITIONS ${PC_LIBMAXMINDDB_CFLAGS_OTHER})
endif()

FIND_PATH(MAXMINDDB_INCLUDE_DIR maxminddb.h
  HINTS
    ${PC_LIBMAXMINDDB_INCLUDEDIR} ${PC_LIBMAXMINDDB_INCLUDE_DIRS}
     "${MAXMINDDB_HINTS}/include"
  PATH_SUFFIXES maxminddb
)

find_library(MAXMINDDB_LIBRARY
  NAMES
    maxminddb libmaxminddb libmaxminddb-0
  HINTS
    ${PC_LIBMAXMINDDB_LIBDIR} ${PC_LIBMAXMINDDB_LIBRARY_DIRS}
    "${MAXMINDDB_HINTS}/lib"
)

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set MAXMINDDB_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(MaxMindDB DEFAULT_MSG
                                  MAXMINDDB_LIBRARY MAXMINDDB_INCLUDE_DIR)

IF(MAXMINDDB_FOUND)
  INCLUDE(CMakePushCheckState)
  CMAKE_PUSH_CHECK_STATE()
  SET(MAXMINDDB_LIBRARIES ${MAXMINDDB_LIBRARY} )
  SET(MAXMINDDB_INCLUDE_DIRS ${MAXMINDDB_INCLUDE_DIR} )
  INCLUDE(CheckFunctionExists)
  SET(CMAKE_REQUIRED_INCLUDES ${MAXMINDDB_INCLUDE_DIRS})
  SET(CMAKE_REQUIRED_LIBRARIES ${MAXMINDDB_LIBRARIES})
  CMAKE_POP_CHECK_STATE()
  if (WIN32)
    set ( MAXMINDDB_DLL_DIR "${MAXMINDDB_HINTS}/bin"
      CACHE PATH "Path to the MaxMindDB DLL"
    )
    file( GLOB _MAXMINDDB_dll RELATIVE "${MAXMINDDB_DLL_DIR}"
      "${MAXMINDDB_DLL_DIR}/libmaxminddb-*.dll"
    )
    set ( MAXMINDDB_DLL ${_MAXMINDDB_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "MaxMindDB DLL file name"
    )
    mark_as_advanced( MAXMINDDB_DLL_DIR MAXMINDDB_DLL )
  endif()
ELSE(MAXMINDDB_FOUND)
  SET(MAXMINDDB_LIBRARIES )
  SET(MAXMINDDB_INCLUDE_DIRS )
  SET(MAXMINDDB_DLL_DIR )
  SET(MAXMINDDB_DLL )
ENDIF(MAXMINDDB_FOUND)

MARK_AS_ADVANCED( MAXMINDDB_LIBRARIES MAXMINDDB_INCLUDE_DIRS )
