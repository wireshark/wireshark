#
# - Find libsinsp and libscap
# Find libsinsp and libscap includes and libraries.
# Adapted from FindZSTD.cmake.
#
# This module will look for libsinsp and libscap using pkg-config. If that
# fails, it will search ${SINSP_INCLUDEDIR} and ${SINSP_HINTS}/include
# for the libsinsp and libscap include directory and ${SINSP_LIBDIR} and
# ${SINSP_HINTS}/lib for the libsinsp and libscap libraries.
#
# It will set the following variables:
#
#  SINSP_FOUND          - True if libsinsp found.
#  SINSP_INCLUDE_DIRS   - Where to find sinsp.h, scap.h, etc.
#  SINSP_LINK_LIBRARIES - List of libraries when using libsinsp.

# You must manually set the following variables:
#  FALCO_PLUGINS        - Paths to plugins built from https://github.com/falcosecurity/plugins/.

# To do:
#  SINSP_DLL_DIR        - (Windows) Path to the libsinsp and libscap DLLs
#  SINSP_DLL            - (Windows) Name of the libsinsp and libscap DLLs

include( FindWSWinLibs )
FindWSWinLibs( "falcosecurity-libs-.*" SINSP_HINTS )

include(CMakeDependentOption)

if( NOT USE_REPOSITORY)
  find_package(PkgConfig)
  pkg_check_modules(SINSP libsinsp)
endif()

# Include both legacy (#include <sinsp.h>) and current (#include <libsinsp/sinsp.h>) paths for now.
if(NOT SINSP_FOUND)
  # pkg_check_modules didn't work, so look for ourselves.
  find_path(_sinsp_include_dirs NO_CACHE
    NAMES libsinsp/sinsp.h
    HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
    PATH_SUFFIXES falcosecurity
    /usr/include
    /usr/local/include
  )
  if(_sinsp_include_dirs)
    list(APPEND _sinsp_include_dirs ${_sinsp_include_dirs}/libsinsp)
  endif()

  find_path(_scap_include_dir NO_CACHE
    NAMES scap.h
    HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
    PATH_SUFFIXES falcosecurity/libscap
    /usr/include
    /usr/local/include
  )
  if(_scap_include_dir)
    list(APPEND _sinsp_include_dirs ${_scap_include_dir})
  endif()
  unset(_scap_include_dir)

  find_library(_sinsp_link_libs NO_CACHE
    NAMES sinsp
    HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib"
    PATHS falcosecurity
    /usr/lib
    /usr/local/lib
  )

  set(_scap_libs
    scap
    scap_engine_nodriver
    scap_engine_noop
    scap_engine_savefile
    scap_engine_source_plugin
    scap_engine_test_input
    scap_error
    scap_event_schema
    scap_platform_util
  )

  foreach(_scap_lib ${_scap_libs})
    find_library(_lib NO_CACHE
      NAMES ${_scap_lib}
      HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib"
      PATHS falcosecurity
      /usr/lib
      /usr/local/lib
    )
    if (_lib)
      list(APPEND _sinsp_link_libs ${_lib})
      unset(_lib)
    endif()
  endforeach()
  unset(_scap_libs)
  unset(_scap_lib)

  find_path(_jsoncpp_include_dir NO_CACHE
    NAMES json/json.h
    HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
    PATH_SUFFIXES falcosecurity jsoncpp
    PATHS
    /usr/include
    /usr/local/include
  )
  if (_jsoncpp_include_dir)
    list(APPEND _sinsp_include_dirs ${_jsoncpp_include_dir})
    unset(_jsoncpp_include_dir)
  endif()

  find_library(_jsoncpp_lib NO_CACHE
    NAMES jsoncpp
    HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib" "${SINSP_HINTS}/lib/falcosecurity"
    PATHS
    /usr/lib
    /usr/local/lib
  )
  if (_jsoncpp_lib)
    list(APPEND _sinsp_link_libs ${_jsoncpp_lib})
    unset(_jsoncpp_lib)
  endif()

  find_library(_re2_lib NO_CACHE
    NAMES re2
    HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib" "${SINSP_HINTS}/lib/falcosecurity"
    PATHS
    /usr/lib
    /usr/local/lib
  )
  if (_re2_lib)
    list(APPEND _sinsp_link_libs ${_re2_lib})
    unset(_re2_lib)
  endif()

  find_path(_tbb_include_dir NO_CACHE
    NAMES tbb/tbb.h
    HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
    PATHS
    /usr/include
    /usr/local/include
  )
  if (_tbb_include_dir)
    list(APPEND _sinsp_include_dirs ${_tbb_include_dir})
    unset(_tbb_include_dir)
  endif()

  find_library(_tbb_lib NO_CACHE
    NAMES tbb tbb12
    HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib" "${SINSP_HINTS}/lib/falcosecurity"
    PATHS
    /usr/lib
    /usr/local/lib
  )
  if (_tbb_lib)
    list(APPEND _sinsp_link_libs ${_tbb_lib})
    unset(_tbb_lib)
  endif()

  # This is terrible, but libsinsp/libscap doesn't support dynamic linking on Windows (yet).
  find_path(_zlib_include_dir NO_CACHE
    NAMES zlib/zlib.h
    HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
    PATHS
    /usr/include
    /usr/local/include
  )
  if (_zlib_include_dir)
    list(APPEND _sinsp_include_dirs ${_zlib_include_dir})
    unset(_zlib_include_dir)
  endif()

  find_library(_zlib_lib NO_CACHE
    NAMES zlibstatic
    HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib" "${SINSP_HINTS}/lib/falcosecurity"
    PATHS
    /usr/lib
    /usr/local/lib
  )
  if (_zlib_lib)
    list(APPEND _sinsp_link_libs ${_zlib_lib})
    unset(_zlib_lib)
  endif()

  if(_sinsp_include_dirs AND _sinsp_link_libs)
    list(REMOVE_DUPLICATES _sinsp_include_dirs)
    set(SINSP_INCLUDE_DIRS ${_sinsp_include_dirs} CACHE PATH "Paths to libsinsp and libscap headers")
    set(SINSP_LINK_LIBRARIES ${_sinsp_link_libs} CACHE PATH "Paths to libsinsp, libscap, etc.")
    set(SINSP_FOUND 1)
    unset(_sinsp_include_dirs)
    unset(_sinsp_link_libs)
  endif()

endif()

# As https://cmake.org/cmake/help/latest/command/link_directories.html
# says, "Prefer to pass full absolute paths to libraries where possible,
# since this ensures the correct library will always be linked," so use
# SINSP_LINK_LIBRARIES instead of SINSP_LIBRARIES
# XXX SINSP_VERSION will require peeking for a #define or something similar.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Sinsp
  REQUIRED_VARS
    SINSP_INCLUDE_DIRS
    SINSP_LINK_LIBRARIES
  # VERSION_VAR SINSP_VERSION
)

if(SINSP_FOUND)
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
  set(SINSP_INCLUDE_DIRS)
  set(SINSP_LINK_LIBRARIES)
endif()

mark_as_advanced(SINSP_INCLUDE_DIRS SINSP_LINK_LIBRARIES)

# Windows plugins

set(_falco_plugins)
if(WIN32 AND SINSP_FOUND AND NOT FALCO_PLUGINS)
  FindWSWinLibs( "falcosecurity-plugins-.*" _falco_plugin_dir)
  if(_falco_plugin_dir)
    file( GLOB _falco_plugins LIST_DIRECTORIES false "${_falco_plugin_dir}/*.dll" )
    unset(_falco_plugin_dir)
  endif()
endif()

# XXX It looks like we can either autodiscover this value or provide an option but not both.
if(_falco_plugins)
  set(FALCO_PLUGINS ${_falco_plugins} CACHE FILEPATH "Paths to Falco plugins. Semicolon-separated")
  unset(_falco_plugins)
else()
  cmake_dependent_option(FALCO_PLUGINS "Paths to Falco plugins. Semicolon-separated" "" "SINSP_FOUND" "")
endif()
