# - Try to find GTK3
#
# $Id$
#
# Once done this will define
#
#  GTK3_FOUND - System has GTK3
#  GTK3_INCLUDE_DIRS - The GTK3 include directory
#  GTK3_LIBRARIES - The libraries needed to use GTK3
#  GTK3_DEFINITIONS - Compiler switches required for using GTK3
#=============================================================================
# Copyright 2011 Duncan Mac-Vicar P. <duncan@kde.org>
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================
# (To distribute this file outside of CMake, substitute the full
#  License text for the above reference.)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("gtk3" "GTK3_HINTS")

# use pkg-config to get the directories and then use these values
# in the FIND_PATH() and FIND_LIBRARY() calls
FIND_PACKAGE(PkgConfig)
PKG_CHECK_MODULES(PC_GTK3 gtk+-3.0 QUIET)

# MESSAGE(STATUS "PC_GTK3_LIBRARIES: ${PC_GTK3_LIBRARIES}")
# MESSAGE(STATUS "PC_GTK3_LIBRARY_DIRS: ${PC_GTK3_LIBRARY_DIRS}")
# MESSAGE(STATUS "PC_GTK3_LDFLAGS: ${PC_GTK3_LDFLAGS}")
# MESSAGE(STATUS "PC_GTK3_LDFLAGS_OTHER: ${PC_GTK3_LDFLAGS_OTHER}")

SET(GTK3_DEFINITIONS ${PC_GTK3_CFLAGS_OTHER})

FIND_PATH(GTK3_INCLUDE_DIR
    NAMES
        "gtk/gtk.h"
        "gtk.h"
    HINTS
        ${GTK3_HINTS}/include
        ${PC_GTK3_INCLUDEDIR}
        ${PC_GTK3_INCLUDE_DIRS}
   PATH_SUFFIXES
        "gtk-3.0"
   )

FIND_LIBRARY(GTK3_LIBRARY
    NAMES
        gtk-3 gtk3
    HINTS
        ${GTK3_HINTS}/lib
        ${PC_GTK3_LIBDIR}
        ${PC_GTK3_LIBRARY_DIRS}
   )

# handle the QUIETLY and REQUIRED arguments and set GTK3_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GTK3 DEFAULT_MSG GTK3_LIBRARY GTK3_INCLUDE_DIR)

if( GTK3_FOUND )
    set( GTK3_LIBRARIES ${GTK3_LIBRARY} )
    set( GTK3_INCLUDE_DIRS ${GTK3_INCLUDE_DIR} )
else()
    set( GTK3_LIBRARIES )
    set( GTK3_INCLUDE_DIRS )
endif()

MARK_AS_ADVANCED(GTK3_INCLUDE_DIRS GTK3_LIBRARIES)

