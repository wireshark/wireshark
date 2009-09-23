#
# $Id$
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


FIND_PATH(LUA_INCLUDE_DIR lua.h
  HINTS
  $ENV{LUA_DIR}
  PATH_SUFFIXES include/lua51 include/lua5.1 include/lua include
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

FIND_LIBRARY(LUA_LIBRARY 
  NAMES lua51 lua5.1 lua
  HINTS
  $ENV{LUA_DIR}
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

IF(LUA_LIBRARY)
  SET( LUA_LIBRARIES "${LUA_LIBRARY}" CACHE STRING "Lua Libraries")
  SET( LUA_INCLUDE_DIRS ${LUA_INCLUDE_DIR} )
ELSE(LUA_LIBRARY)
  SET( LUA_LIBRARIES )
  SET( LUA_INCLUDE_DIRS )
ENDIF(LUA_LIBRARY)

MARK_AS_ADVANCED(LUA_INCLUDE_DIRS LUA_LIBRARIES)

