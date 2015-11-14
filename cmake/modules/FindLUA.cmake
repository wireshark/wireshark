#
# Locate Lua library
# This module defines
#  LUA_FOUND        - If false, do not try to link to Lua
#  LUA_LIBRARIES
#  LUA_INCLUDE_DIRS - Where to find lua.h
#  LUA_DLL_DIR      - (Windows) Path to the Lua DLL.
#  LUA_DLL          - (Windows) Name of the Lua DLL.
#
# Note that the expected include convention is
#  #include "lua.h"
# and not
#  #include <lua/lua.h>
# This is because, the lua location is not standardized and may exist
# in locations other than lua/

INCLUDE(FindWSWinLibs)
FindWSWinLibs("lua5*" "LUA_HINTS")

find_package(PkgConfig)
pkg_search_module(LUA lua5.2 lua-5.2 lua52 lua5.1 lua-5.1 lua51 lua5.0 lua-5.0 lua50)
if(NOT LUA_FOUND)
    pkg_search_module(LUA "lua<=5.2.99")
endif()

FIND_PATH(LUA_INCLUDE_DIR lua.h
  HINTS
    "${LUA_INCLUDEDIR}"
    "$ENV{LUA_DIR}"
  ${LUA_HINTS}
  PATH_SUFFIXES include/lua52 include/lua5.2 include/lua51 include/lua5.1 include/lua include
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local
  /usr
  /sw # Fink
  /opt/local # DarwinPorts
  /opt/csw # Blastwave
  /opt
)

if(LUA_INCLUDE_DIR AND EXISTS "${LUA_INCLUDE_DIR}/lua.h")
  file(STRINGS "${LUA_INCLUDE_DIR}/lua.h" LUA_VERSION_NUM REGEX "LUA_VERSION_NUM")
  if (LUA_VERSION_NUM)
    string(REGEX REPLACE "^#define[ \t]+LUA_VERSION_NUM[ \t]+([0-9]+)" "\\1"
      LUA_VERSION_NUM "${LUA_VERSION_NUM}")
  else()
    set( LUA_VERSION_NUM "500")
  endif()
endif()
string( REGEX REPLACE ".*[/\\]lua(.+)$" "\\1" LUA_INC_SUFFIX "${LUA_INCLUDE_DIR}" )
if ( LUA_INCLUDE_DIR STREQUAL LUA_INC_SUFFIX )
  set( LUA_INC_SUFFIX "")
endif()

FIND_LIBRARY(LUA_LIBRARY
  NAMES lua${LUA_INC_SUFFIX} lua52 lua5.2 lua51 lua5.1 lua
  HINTS
    "${LUA_LIBDIR}"
    "$ENV{LUA_DIR}"
    ${LUA_HINTS}
  PATH_SUFFIXES lib64 lib
  PATHS
    ~/Library/Frameworks
    /Library/Frameworks
    /usr/local
    /usr
    /sw
    /opt/local
    /opt/csw
    /opt
)

# Lua 5.3 is not supported, only 5.0/5.1/5.2 are (due to bitops problem)
if(LUA_VERSION_NUM GREATER 502)
  set(LUA_VERSION_NUM)
endif()

INCLUDE(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LUA_FOUND to TRUE if
# all listed variables are TRUE
find_package_handle_standard_args(LUA
  REQUIRED_VARS LUA_LIBRARY LUA_INCLUDE_DIR LUA_VERSION_NUM
  VERSION_VAR   LUA_VERSION_NUM)

IF(LUA_LIBRARY)
  SET( LUA_LIBRARIES "${LUA_LIBRARY}")
  SET( LUA_INCLUDE_DIRS ${LUA_INCLUDE_DIR} )
  if (WIN32)
    set ( LUA_DLL_DIR "${LUA_HINTS}"
      CACHE PATH "Path to Lua DLL"
    )
    file( GLOB _lua_dll RELATIVE "${LUA_DLL_DIR}"
      "${LUA_DLL_DIR}/lua*.dll"
    )
    set ( LUA_DLL ${_lua_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "Lua DLL file name"
    )
    mark_as_advanced( LUA_DLL_DIR LUA_DLL )
  endif()
ELSE(LUA_LIBRARY)
  SET( LUA_LIBRARIES )
  SET( LUA_INCLUDE_DIRS )
  SET( LUA_DLL_DIR )
  SET( LUA_DLL )
ENDIF(LUA_LIBRARY)

MARK_AS_ADVANCED(LUA_INCLUDE_DIRS LUA_LIBRARIES)
