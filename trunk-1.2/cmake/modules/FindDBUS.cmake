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
# - Locate D-Bus include paths and libraries.
#  D-Bus can be found at http://www.freedesktop.org/wiki/Software/dbus.
#  Written by Frederic Heem, frederic.heem _at_ telsey.it
#
# This module defines:
#  DBUS_FOUND, true if D-Bus has been found
#  DBUS_VERSION, the D-Bus version 
#  DBUS_INCLUDE_DIRS, where to find ptlib.h, etc.
#  DBUS_LIBRARIES, library to link againt D-Bus
#  DBUS_DEFINITIONS, the definitions used to compile D-Bus

INCLUDE(UsePkgConfig)

#Keep space in of $ENV{PKG_CONFIG_PATH} is empty
SET(PKG_CONFIG_PATH " $ENV{PKG_CONFIG_PATH}")


#Find the D-Bus package
PKGCONFIG_FOUND(dbus-1 ${PKG_CONFIG_PATH} DBUS_FOUND)

IF(DBUS_FOUND)
  MESSAGE(STATUS "D-Bus found")
ELSE(DBUS_FOUND)
  MESSAGE(FATAL "D-Bus cannot be found")
ENDIF(DBUS_FOUND)

#Include

PKGCONFIG_INCLUDE_DIRS(dbus-1 ${PKG_CONFIG_PATH} DBUS_INCLUDE_DIRS_PKGCONFIG)

MESSAGE(STATUS ${DBUS_INCLUDE_DIRS_PKGCONFIG})

FIND_PATH(DBUS_INCLUDE_DIR dbus/dbus.h
  PATHS
    ${DBUS_INCLUDE_DIRS_PKGCONFIG}
    /usr/include/dbus-1.0
  DOC
    "Path to dbus include file dbus/dbus.h"
  NO_DEFAULT_PATH
)

IF(DBUS_INCLUDE_DIR)
  MESSAGE(STATUS "D-Bus include dir set to ${DBUS_INCLUDE_DIR}")
ELSE(DBUS_INCLUDE_DIR)
  MESSAGE(FATAL "D-Bus include dirs cannot be found")
ENDIF(DBUS_INCLUDE_DIR)

FIND_PATH(DBUS_INCLUDE_DIR_ARCH dbus/dbus-arch-deps.h
  PATHS
    ${DBUS_INCLUDE_DIRS_PKGCONFIG}
    /usr/lib/dbus-1.0/include
  DOC
    "Path to dbus include file dbus/dbus-arch-deps.h"
  NO_DEFAULT_PATH
)

IF(DBUS_INCLUDE_DIR_ARCH)
  MESSAGE(STATUS "D-Bus architecture include dir set to ${DBUS_INCLUDE_DIR_ARCH}")
ELSE(DBUS_INCLUDE_DIR_ARCH)
  MESSAGE(FATAL " D-Bus architecture include dirs cannot be found")
ENDIF(DBUS_INCLUDE_DIR_ARCH)

SET(DBUS_INCLUDE_DIRS ${DBUS_INCLUDE_DIR} ${DBUS_INCLUDE_DIR_ARCH})

#Library
PKGCONFIG_LIBRARY_DIR(dbus-1 ${PKG_CONFIG_PATH}  DBUS_LIBRARY_DIR)

SET(DBUS_LIB_PATH_DESCRIPTION "The directory containing the dbus library. E.g /home/fred/dbus/lib or c:\\dbus\\lib")

FIND_LIBRARY(DBUS_LIBRARY
  NAMES 
    dbus-1
  PATHS
    ${DBUS_LIBRARY_DIR}
  DOC 
    ${DBUS_LIB_PATH_DESCRIPTION}
  NO_DEFAULT_PATH
)

SET(DBUS_LIBRARIES ${DBUS_LIBRARY}) 

IF(DBUS_LIBRARIES)
  MESSAGE(STATUS "D-Bus library set to  ${DBUS_LIBRARIES}")
ELSE(DBUS_LIBRARIES)
  MESSAGE(FATAL "D-Bus library cannot be found")
ENDIF(DBUS_LIBRARIES)

#Version
PKGCONFIG_VERSION(dbus-1 ${PKG_CONFIG_PATH} DBUS_VERSION)
MESSAGE(STATUS "D-Bus version is ${DBUS_VERSION}")

#Definition
PKGCONFIG_DEFINITION(dbus-1 ${PKG_CONFIG_PATH} DBUS_DEFINITIONS)
MESSAGE(STATUS "D-Bus definitions are ${DBUS_DEFINITIONS}")


MARK_AS_ADVANCED(
  DBUS_INCLUDE_DIR
  DBUS_INCLUDE_DIR_ARCH
  DBUS_LIBRARY
) 
