# - Try to find XXHASH
# Once done, this will define
#
#  XXHASH_FOUND - system has XXHASH
#  XXHASH_INCLUDE_DIRSS - the XXHASH include directories
#  XXHASH_LIBRARIES - the XXHASH library

include( FindWSWinLibs )
FindWSWinLibs( "xxhash" "XXHASH_HINTS" )

if (NOT USE_REPOSITORY) # else we'll find Strawberry Perl's pkgconfig
    find_package(PkgConfig)
    pkg_search_module(xxhash libxxhash)
endif()

find_path(XXHASH_INCLUDE_DIR
    NAMES xxhash.h
    HINTS
        ${XXHASH_INCLUDEDIR}
        ${XXHASH_HINTS}/include
    PATHS
        ${XXHASH_PKGCONF_INCLUDE_DIRS}
        /usr/include
        /usr/local/include
)

if(XXHASH_INCLUDE_DIR AND EXISTS "${XXHASH_INCLUDE_DIR}/xxhash.h")
  file(STRINGS "${XXHASH_INCLUDE_DIR}/xxhash.h" XXHASH_H REGEX "^#define XXH_VERSION_[A-Z]+[ ]+[0-9]+$")
  string(REGEX REPLACE ".+XXH_VERSION_MAJOR[ ]+([0-9]+).*$"   "\\1" XXHASH_VERSION_MAJOR "${XXHASH_H}")
  string(REGEX REPLACE ".+XXH_VERSION_MINOR[ ]+([0-9]+).*$"   "\\1" XXHASH_VERSION_MINOR "${XXHASH_H}")
  string(REGEX REPLACE ".+XXH_VERSION_RELEASE[ ]+([0-9]+).*$" "\\1" XXHASH_VERSION_PATCH "${XXHASH_H}")
  set(XXHASH_VERSION_STRING "${XXHASH_VERSION_MAJOR}.${XXHASH_VERSION_MINOR}.${XXHASH_VERSION_PATCH}")
endif()

find_library(XXHASH_LIBRARY
    NAMES xxhash
    HINTS
        ${XXHASH_LIBDIR}
        ${XXHASH_HINTS}/lib
    PATHS
        ${XXHASH_PKGCONF_LIBRARY_DIRS}
        /usr/lib
        /usr/local/lib

)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(XXHASH
    REQUIRED_VARS   XXHASH_LIBRARY XXHASH_INCLUDE_DIR
    VERSION_VAR     XXHASH_VERSION_STRING
)


mark_as_advanced(XXHASH_INCLUDE_DIR XXHASH_LIBRARY)

if(XXHASH_FOUND)
    AddWSWinDLL(XXHASH XXHASH_HINTS "xxhash")
    SET(XXHASH_INCLUDE_DIRS ${XXHASH_INCLUDE_DIR})
    SET(XXHASH_LIBRARIES ${XXHASH_LIBRARY})
else()
    SET(XXHASH_LIBRARIES )
    SET(XXHASH_INCLUDE_DIRS )
endif()
