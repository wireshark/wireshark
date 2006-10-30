###################################################################
#
#  Copyright (c) 2006 Frederic Heem, <frederic.heem@telsey.it>
#  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# * Neither the name of the Telsey nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
###################################################################
# - Locate dbus-glib-1 include paths and libraries
#  dbus-glib-1 can be found at http://www.freedesktop.org/wiki/Software/dbus
#  Written by Frederic Heem, frederic.heem _at_ telsey.it

# This module defines
#  DBUSGLIBGLIB_FOUND, true if dbus-glib-1 has been found
#  DBUSGLIBGLIB_VERSION, the dbus-glib-1 version 
#  DBUSGLIBGLIB_INCLUDE_DIRS, where to find dbus/dbus-glib.h, etc.
#  DBUSGLIBGLIB_LIBRARIES, library to link againt libdbus-glib-1
#  DBUSGLIBGLIB_DEFINITIONS, the definitions used to compile dbus-glib-1

#D-Bus is required by dbus-glib-1
FIND_PACKAGE(DBUS REQUIRED)

#Keep space in of $ENV{PKG_CONFIG_PATH} is empty
SET(PKG_CONFIG_PATH " $ENV{PKG_CONFIG_PATH}")

#Find the D-Bus package
PKGCONFIG_FOUND(dbus-1 ${PKG_CONFIG_PATH} DBUSGLIB_FOUND)

IF(DBUSGLIB_FOUND)
  MESSAGE(STATUS "D-Bus glib found")
ELSE(DBUSGLIB_FOUND)
  MESSAGE(FATAL "D-Bus glib cannot be found")
ENDIF(DBUSGLIB_FOUND)

#Includes
PKGCONFIG_INCLUDE_DIRS(dbus-glib-1 ${PKG_CONFIG_PATH} DBUSGLIB_INCLUDE_DIRS_PKGCONFIG)

#TODO 
FIND_PATH(DBUSGLIB_INCLUDE_DIR dbus/dbus-glib.h
  PATHS
    ${DBUSGLIB_INCLUDE_DIRS_PKGCONFIG}
    /usr/include/dbus-1.0
  DOC
    "Path to dbus glib include file dbus-glib.h"
  NO_DEFAULT_PATH
)

SET(DBUSGLIB_INCLUDE_DIRS ${DBUSGLIB_INCLUDE_DIR} ${DBUS_INCLUDE_DIRS})

IF(DBUSGLIB_INCLUDE_DIR)
  MESSAGE(STATUS "D-Bus glib include dir set to ${DBUSGLIB_INCLUDE_DIR}")
ELSE(DBUSGLIB_INCLUDE_DIR)
  MESSAGE(FATAL "D-Bus glib include dir cannot be found")
ENDIF(DBUSGLIB_INCLUDE_DIR)

#Library
PKGCONFIG_LIBRARY_DIR(dbus-glib-1 ${PKG_CONFIG_PATH}  DBUSGLIB_LIBRARY_DIR)

SET(DBUSGLIB_LIB_PATH_DESCRIPTION "The directory containing the dbus glib library. E.g /home/fred/dbus-glib/lib or c:\\dbus-glib\\lib")

FIND_LIBRARY(DBUSGLIB_LIBRARY
  NAMES 
    dbus-glib-1
  PATHS
    ${DBUSGLIB_LIBRARY_DIR}
  DOC 
    ${DBUSGLIB_LIB_PATH_DESCRIPTION}
  NO_DEFAULT_PATH
)

SET(DBUSGLIB_LIBRARIES ${DBUSGLIB_LIBRARY} ${DBUS_LIBRARIES}) 

IF(DBUSGLIB_LIBRARIES)
  MESSAGE(STATUS "D-Bus glib library set to  ${DBUSGLIB_LIBRARIES}")
ELSE(DBUSGLIB_LIBRARIES)
  MESSAGE(FATAL "D-Bus glib library cannot be found")
ENDIF(DBUSGLIB_LIBRARIES)

#Version
PKGCONFIG_VERSION(dbus-glib-1 ${PKG_CONFIG_PATH} DBUSGLIB_VERSION)
MESSAGE(STATUS "D-Bus glib version is ${DBUSGLIB_VERSION}")

#Definition
PKGCONFIG_DEFINITION(dbus-glib-1 ${PKG_CONFIG_PATH} DBUSGLIB_DEFINITIONS)
MESSAGE(STATUS "D-Bus glib definitions are ${DBUSGLIB_DEFINITIONS}")

#binding tool
FIND_PROGRAM(DBUSGLIB_BINDING_TOOL_EXECUTABLE
  NAMES 
    dbus-binding-tool
)

MARK_AS_ADVANCED(
  DBUSGLIB_INCLUDE_DIR
  DBUSGLIB_LIBRARY
  DBUSGLIB_BINDING_TOOL_EXECUTABLE
) 
