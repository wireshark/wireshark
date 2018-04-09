# - Try to find JsonGlib-1.0
# Once done, this will define
#
#  JSONGLIB_FOUND - system has Glib
#  JSONGLIB_INCLUDE_DIRS - the Glib include directories
#  JSONGLIB_LIBRARIES - link these to use Glib

include(FindWSWinLibs)
FindWSWinLibs("libjson-glib-.*" "JSONGLIB_HINTS")

find_path(JSONGLIB_INCLUDE_DIR
    NAMES
      json-glib/json-glib.h
    HINTS
      ${JSONGLIB_HINTS}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
    PATH_SUFFIXES
      json-glib-1.0
)

find_library(JSONGLIB_LIBRARY
    NAMES
      json-glib-1.0
      json-glib-1.0-0
    HINTS
      ${JSONGLIB_HINTS}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
)

if(WIN32)
    set(JSONGLIB_DLL_DIR "${JSONGLIB_HINTS}/bin"
      CACHE PATH "Path to libjson-glib DLL"
    )
    file(GLOB _libssh_dll RELATIVE "${JSONGLIB_DLL_DIR}"
      "${JSONGLIB_DLL_DIR}/json-glib-1.0.dll"
    )
    set(JSONGLIB_DLL ${_jsonglib_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "libjson-glib DLL file name"
    )
    mark_as_advanced(JSONGLIB_DLL_DIR JSONGLIB_DLL)
endif()

if(JSONGLIB_INCLUDE_DIR AND JSONGLIB_LIBRARY)
    set(JSONGLIB_INCLUDE_DIRS
      ${JSONGLIB_INCLUDE_DIR}
    )
    set(JSONGLIB_LIBRARIES
      ${JSONGLIB_LIBRARY}
    )
endif()

# handle the QUIETLY and REQUIRED arguments and set JSONGLIB_FOUND to TRUE if
# all listed variables are TRUE and the requested version matches.
include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(JSONGLIB
	REQUIRED_VARS   JSONGLIB_LIBRARY JSONGLIB_INCLUDE_DIR)
