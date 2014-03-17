#
# Locate Lua library
# This module defines
#  LUA_FOUND, if false, do not try to link to Lua 
#  LUA_LIBRARIES
#  LUA_INCLUDE_DIRS, where to find lua.h 
#
# Note that the expected include convention is
#  #include "lua.h"
# and not
#  #include <lua/lua.h>
# This is because, the lua location is not standardized and may exist
# in locations other than lua/

INCLUDE(FindWSWinLibs)
FindWSWinLibs("lua5*" "LUA_HINTS")

FIND_PATH(LUA_INCLUDE_DIR lua.h
  HINTS
  $ENV{LUA_DIR}
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
  file(STRINGS "${LUA_INCLUDE_DIR}/lua.h" LUA_VERSION REGEX "LUA_VERSION_NUM")
  if (LUA_VERSION)
    string(REGEX REPLACE "^#define[ \t]+LUA_VERSION_NUM[ \t]+(.+)" "\\1" LUA_VERSION "${LUA_VERSION}")
  else()
    set( LUA_VERSION "500")
  endif()
endif()
string( REGEX REPLACE ".*[/\\]lua(.+)$" "\\1" LUA_INC_SUFFIX "${LUA_INCLUDE_DIR}" )
if ( LUA_INCLUDE_DIR STREQUAL LUA_INC_SUFFIX )
  set( LUA_INC_SUFFIX "")
endif()
message("LUA INCLUDE SUFFIX: ${LUA_INC_SUFFIX}")


FIND_LIBRARY(LUA_LIBRARY
  NAMES lua${LUA_INC_SUFFIX} lua52 lua5.2 lua51 lua5.1 lua
  HINTS
  $ENV{LUA_DIR}
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

INCLUDE(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LUA_FOUND to TRUE if 
# all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LUA  DEFAULT_MSG  LUA_LIBRARY LUA_INCLUDE_DIR)
message("LUA INCLUDEs version: ${LUA_VERSION}")

IF(LUA_LIBRARY)
  SET( LUA_LIBRARIES "${LUA_LIBRARY}" CACHE STRING "Lua Libraries")
  SET( LUA_INCLUDE_DIRS ${LUA_INCLUDE_DIR} )
ELSE(LUA_LIBRARY)
  SET( LUA_LIBRARIES )
  SET( LUA_INCLUDE_DIRS )
ENDIF(LUA_LIBRARY)

MARK_AS_ADVANCED(LUA_INCLUDE_DIRS LUA_LIBRARIES)

