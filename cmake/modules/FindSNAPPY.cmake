#
# - Find snappy
# Find Snappy includes and library
#
#  SNAPPY_INCLUDE_DIRS - where to find snappy.h, etc.
#  SNAPPY_LIBRARIES    - List of libraries when using Snappy.
#  SNAPPY_FOUND        - True if Snappy found.
#  SNAPPY_DLL_DIR      - (Windows) Path to the Snappy DLL
#  SNAPPY_DLL          - (Windows) Name of the Snappy DLL

include( FindWSWinLibs )
FindWSWinLibs( "snappy-.*" "SNAPPY_HINTS" )

if( NOT USE_REPOSITORY)
  find_package(PkgConfig QUIET)
  pkg_search_module(SNAPPY QUIET libsnappy)
endif()

find_path(SNAPPY_INCLUDE_DIR
  NAMES snappy.h
  HINTS "${SNAPPY_INCLUDEDIR}" "${SNAPPY_HINTS}/include"
  /usr/include
  /usr/local/include
)

find_library(SNAPPY_LIBRARY
  NAMES snappy
  HINTS "${SNAPPY_LIBDIR}" "${SNAPPY_HINTS}/lib"
  PATHS
  /usr/lib
  /usr/local/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args( SNAPPY DEFAULT_MSG SNAPPY_LIBRARY SNAPPY_INCLUDE_DIR )

if( SNAPPY_FOUND )
  set( SNAPPY_INCLUDE_DIRS ${SNAPPY_INCLUDE_DIR} )
  set( SNAPPY_LIBRARIES ${SNAPPY_LIBRARY} )
    set(_snappy_version_header "${SNAPPY_INCLUDE_DIR}/snappy-stubs-public.h")

    file(STRINGS "${_snappy_version_header}" SNAPPY_VERSION_MAJOR
    REGEX "#define[ ]+SNAPPY_MAJOR[ ]+[0-9]+")
    # Older versions of snappy like snappy-0.2 have SNAPPY_VERSION but not SNAPPY_VERSION_MAJOR
    if(SNAPPY_VERSION_MAJOR)
    string(REGEX MATCH "[0-9]+" SNAPPY_VERSION_MAJOR ${SNAPPY_VERSION_MAJOR})
    file(STRINGS "${_snappy_version_header}" SNAPPY_VERSION_MINOR
    REGEX "#define[ ]+SNAPPY_MINOR[ ]+[0-9]+")
    string(REGEX MATCH "[0-9]+" SNAPPY_VERSION_MINOR ${SNAPPY_VERSION_MINOR})
    file(STRINGS "${_snappy_version_header}" SNAPPY_VERSION_PATCH
    REGEX "#define[ ]+SNAPPY_PATCHLEVEL[ ]+[0-9]+")
    string(REGEX MATCH "[0-9]+" SNAPPY_VERSION_PATCH ${SNAPPY_VERSION_PATCH})
    set(SNAPPY_VERSION ${SNAPPY_VERSION_MAJOR}.${SNAPPY_VERSION_MINOR}.${SNAPPY_VERSION_PATCH})
    endif()

  if (WIN32)
    set ( SNAPPY_DLL_DIR "${SNAPPY_HINTS}/bin"
      CACHE PATH "Path to Snappy DLL"
    )
    file( GLOB _snappy_dll RELATIVE "${SNAPPY_DLL_DIR}"
      "${SNAPPY_DLL_DIR}/snappy*.dll"
    )
    set ( SNAPPY_DLL ${_snappy_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "Snappy DLL file name"
    )
    mark_as_advanced( SNAPPY_DLL_DIR SNAPPY_DLL )
  endif()
else()
  set( SNAPPY_INCLUDE_DIRS )
  set( SNAPPY_LIBRARIES )
endif()

mark_as_advanced( SNAPPY_LIBRARIES SNAPPY_INCLUDE_DIRS )
