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
#  SINSP_PLUGINS        - List of plugins.

# To do:
#  SINSP_DLL_DIR        - (Windows) Path to the libsinsp and libscap DLLs
#  SINSP_DLL            - (Windows) Name of the libsinsp and libscap DLLs

include( FindWSWinLibs )
FindWSWinLibs( "libsinsp-.*" "SINSP_HINTS" )

if( NOT WIN32)
  find_package(PkgConfig)
  pkg_check_modules(SINSP libsinsp)
endif()

if(NOT SINSP_FOUND)
  # pkg_check_modules didn't work, so look for ourselves.
  find_path(SINSP_INCLUDE_DIRS
    NAMES sinsp.h
    HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
    PATH_SUFFIXES falcosecurity/userspace/libsinsp
    /usr/include
    /usr/local/include
  )

  find_path(_scap_include_dir
    NAMES scap.h
    HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
    PATH_SUFFIXES falcosecurity/userspace/libscap
    /usr/include
    /usr/local/include
  )
  if(_scap_include_dir)
    list(APPEND SINSP_INCLUDE_DIRS _scap_include_dir)
  endif()
  unset(_scap_include_dir)

  find_library(SINSP_LINK_LIBRARIES
    NAMES sinsp
    HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib"
    PATHS falcosecurity
    /usr/lib
    /usr/local/lib
  )

  set(_scap_libs
    scap
    scap_engine_util
    scap_event_schema
    driver_event_schema
    scap_engine_bpf
    scap_engine_gvisor
    scap_engine_kmod
    scap_engine_nodriver
    scap_engine_noop
    scap_engine_savefile
    scap_engine_source_plugin
    scap_engine_udig
  )

  foreach(_scap_lib ${_scap_libs})
    find_library(_lib
      NAMES ${_scap_lib}
      HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib"
      PATHS falcosecurity
      /usr/lib
      /usr/local/lib
    )
    if (_lib)
      list(APPEND SINSP_LINK_LIBRARIES ${_lib})
    endif()
  endforeach()
  unset(_scap_libs)
  unset(_scap_lib)
  unset(_lib)
  if(SINSP_INCLUDE_DIRS AND JSONCPP_LIBRARY)
    set(SINSP_FOUND 1)
  endif()

  find_path(JSONCPP_INCLUDE_DIR
    NAMES json/json.h
    HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
    PATH_SUFFIXES jsoncpp
    /usr/include
    /usr/local/include
  )
  if (JSON_INCLUDE_DIR)
    list(APPEND SINSP_INCLUDE_DIRS ${JSONCPP_INCLUDE_DIR})
  endif()

  find_library(JSONCPP_LIBRARY
    NAMES jsoncpp
    HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib"
    PATHS
    /usr/lib
    /usr/local/lib
  )
  if (JSONCPP_LIBRARY)
    list(APPEND JSONCPP_LIBRARY ${JSONCPP_LIBRARY})
  endif()

  find_path(TBB_INCLUDE_DIR
    NAMES tbb/tbb.h
    HINTS "${SINSP_INCLUDEDIR}" "${SINSP_HINTS}/include"
    /usr/include
    /usr/local/include
  )
  if (TBB_INCLUDE_DIR)
    list(APPEND SINSP_INCLUDE_DIRS ${TBB_INCLUDE_DIR})
  endif()

  find_library(TBB_LIBRARY
    NAMES tbb
    HINTS "${SINSP_LIBDIR}" "${SINSP_HINTS}/lib"
    PATHS
    /usr/lib
    /usr/local/lib
  )
  if (TBB_LIBRARY)
    list(APPEND JSONCPP_LIBRARY ${TBB_LIBRARY})
  endif()
endif()

find_path(SINSP_PLUGIN_DIR
  NAMES registry.yaml
  HINTS "${SINSP_PLUGINDIR}"
)

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
    SINSP_PLUGIN_DIR
  # VERSION_VAR SINSP_VERSION
)

if(SINSP_FOUND)
  if (WIN32)
    set(SINSP_PLUGINS ${SINSP_PLUGIN_DIR}/plugins/cloudtrail/cloudtrail.dll)
  else()
    set(SINSP_PLUGINS ${SINSP_PLUGIN_DIR}/plugins/cloudtrail/libcloudtrail.so)
  endif()
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
  set(SINSP_PLUGINS)
endif()

mark_as_advanced(SINSP_INCLUDE_DIRS SINSP_LINK_LIBRARIES SINSP_PLUGINS)
