#
# - Try to find libmaxminddb.
# Once done this will define an IMPORTED target MaxMindDB::MaxMindDB
# if libmaxminddb has been found. It will also define the following
# result variables in the project:
#  MAXMINDDB_FOUND - System has libmaxminddb
#  MAXMINDDB_INCLUDE_DIRS - The libmaxminddb include directories
#  MAXMINDDB_LIBRARIES - The libraries needed to use libmaxminddb
#  MAXMINDDB_DEFINITIONS - Compiler switches required for using libmaxminddb
#  MAXMINDDB_DLL_DIR_RELEASE - (Windows) Path to the MaxMindDB Release DLL.
#  MAXMINDDB_DLL_RELEASE     - (Windows) Name of the MaxMindDB Release DLL.
#  MAXMINDDB_DLL_DIR_DEBUG   - (Windows) Path to the MaxMindDB Debug DLL.
#  MAXMINDDB_DLL_DEBUG       - (Windows) Name of the MaxMindDB Debug DLL.
# Some of these variables may be empty; e.g., vcpkg builds libmaxminddb as
# static-only, so the DLL filenames will be empty.

IF (MAXMINDDB_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(MAXMINDDB_FIND_QUIETLY TRUE)
ENDIF (MAXMINDDB_INCLUDE_DIRS)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("libmaxminddb-.*" "MAXMINDDB_HINTS")

IF (NOT USE_REPOSITORY)
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

include(FindWSLibrary)
FindWSLibrary(MAXMINDDB_LIBRARY
  # maxminddbd is the debug library
  NAMES
    maxminddb libmaxminddb libmaxminddb-0 maxminddbd
  HINTS
    ${PC_LIBMAXMINDDB_LIBDIR} ${PC_LIBMAXMINDDB_LIBRARY_DIRS}
  WIN32_HINTS
    ${MAXMINDDB_HINTS}
)

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set MAXMINDDB_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(MaxMindDB DEFAULT_MSG
                                  MAXMINDDB_LIBRARY MAXMINDDB_INCLUDE_DIR)

IF(MAXMINDDB_FOUND)
  SET(MAXMINDDB_LIBRARIES ${MAXMINDDB_LIBRARY} )
  SET(MAXMINDDB_INCLUDE_DIRS ${MAXMINDDB_INCLUDE_DIR} )
  if (USE_REPOSITORY)
    set ( MAXMINDDB_DLL_DIR_RELEASE "${MAXMINDDB_HINTS}/bin"
      CACHE PATH "Path to the MaxMindDB release DLL"
    )
    set ( MAXMINDDB_DLL_DIR_DEBUG "${MAXMINDDB_HINTS}/debug/bin"
      CACHE PATH "Path to the MaxMindDB debug DLL"
    )
    file( GLOB _MAXMINDDB_dll RELATIVE "${MAXMINDDB_DLL_DIR_RELEASE}"
      "${MAXMINDDB_DLL_DIR_RELEASE}/libmaxminddb*.dll"
    )
    set ( MAXMINDDB_DLL_RELEASE ${_MAXMINDDB_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "MaxMindDB DLL file name"
    )
    file( GLOB _MAXMINDDB_dll RELATIVE "${MAXMINDDB_DLL_DIR_DEBUG}"
      "${MAXMINDDB_DLL_DIR_DEBUG}/libmaxminddb*.dll"
    )
    set ( MAXMINDDB_DLL_DEBUG ${_MAXMINDDB_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "MaxMindDB DLL file name"
    )
    mark_as_advanced( MAXMINDDB_DLL_DIR_RELEASE MAXMINDDB_DLL_RELEASE )
    mark_as_advanced( MAXMINDDB_DLL_DIR_DEBUG MAXMINDDB_DLL_DEBUG )
  endif()
  if(MAXMINDDB_INCLUDE_DIR)
    set(_version_regex "^#define[ \t]+PACKAGE_VERSION[ \t]+\"([^\"]+)\".*")
    file(STRINGS "${MAXMINDDB_INCLUDE_DIR}/maxminddb.h" MAXMINDDB_VERSION REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" MAXMINDDB_VERSION "${MAXMINDDB_VERSION}")
    unset(_version_regex)
  endif()
  if (NOT TARGET MaxMindDB::MaxMindDB)
    add_library(MaxMindDB::MaxMindDB UNKNOWN IMPORTED)
    if (USE_REPOSITORY)
      set_target_properties(MaxMindDB::MaxMindDB PROPERTIES
        IMPORTED_CONFIGURATIONS "RELEASE;DEBUG"
        IMPORTED_LOCATION "${MAXMINDDB_LIBRARY_RELEASE}"
        IMPORTED_LOCATION_DEBUG "${MAXMINDDB_LIBRARY_DEBUG}"
        INTERFACE_INCLUDE_DIRECTORIES "${MAXMINDDB_INCLUDE_DIR}"
      )
    else()
      set_target_properties(MaxMindDB::MaxMindDB PROPERTIES
        IMPORTED_LOCATION "${MAXMINDDB_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MAXMINDDB_INCLUDE_DIR}"
        INTERFACE_COMPILE_OPTIONS "${MAXMINDDB_DEFINITIONS}"
      )
    endif()
  endif()
ELSE(MAXMINDDB_FOUND)
  SET(MAXMINDDB_LIBRARIES )
  SET(MAXMINDDB_INCLUDE_DIRS )
  SET(MAXMINDDB_DLL_DIR_RELEASE )
  SET(MAXMINDDB_DLL_RELEASE )
  SET(MAXMINDDB_DLL_DIR_DEBUG )
  SET(MAXMINDDB_DLL_DEBUG )
ENDIF(MAXMINDDB_FOUND)

MARK_AS_ADVANCED( MAXMINDDB_LIBRARIES MAXMINDDB_INCLUDE_DIRS )
