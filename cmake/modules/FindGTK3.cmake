# - Try to find GTK3
#
# Once done this will define
#
#  GTK3_FOUND - System has GTK3
#  GTK3_INCLUDE_DIRS - The GTK3 include directory
#  GTK3_LIBRARIES - The libraries needed to use GTK3
#  GTK3_DEFINITIONS - Compiler switches required for using GTK3
#  GTK3_DLL_DIR - (Windows) Path to required GTK2 DLLS
#  GTK3_DLLS - (Windows) List of required GTK3 DLLS
#  GTK3_ETC_DIR - (Windows) Path to GTK3 configuration files
#  GTK3_LIB_DIR - (Windows) Path to additional GTK3 library files
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

include( FindWSWinLibs )
FindWSWinLibs( "gtk3" "GTK3_HINTS" )
if( DEFINED GTK3_HINTS )
    set( GTK3_PKG_CONFIG_PATH "${GTK3_HINTS}/lib/pkgconfig" )
    file( TO_NATIVE_PATH ${GTK3_PKG_CONFIG_PATH} GTK3_PKG_NATIVE_PATH )

    if ( DEFINED ENV{PKG_CONFIG_PATH} )
        set( ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${GTK3_PKG_NATIVE_PATH}" )
    else()
        set( ENV{PKG_CONFIG_PATH} "${GTK3_PKG_NATIVE_PATH}" )
    endif()
endif()

# use pkg-config to get the directories and then use these values
# in the FIND_PATH() and FIND_LIBRARY() calls
find_package( PkgConfig )
pkg_check_modules( PC_GTK3 QUIET gtk+-3.0 )

# Hack around broken .pc files in Windows GTK bundle
if( DEFINED GTK3_HINTS )
    string( REGEX REPLACE "(-I|^|;)/[^;]*/include" "\\1${GTK3_HINTS}/include" PC_GTK3_INCLUDEDIR "${PC_GTK3_INCLUDEDIR}" )
    string( REGEX REPLACE "(-I|^|;)/[^;]*/include" "\\1${GTK3_HINTS}/include" PC_GTK3_INCLUDE_DIRS "${PC_GTK3_INCLUDE_DIRS}" )
    string( REGEX REPLACE "-L/.*/lib" "-L${GTK3_HINTS}/lib" PC_GTK3_LIBRARY_DIRS "${PC_GTK3_LIBRARY_DIRS}" )
    set( PC_GTK3_CFLAGS )
    set( PC_GTK3_CFLAGS_OTHER )
    file( GLOB _SUBDIRS "${PC_GTK3_INCLUDEDIR}/*" )
    foreach( _ENTRY ${_SUBDIRS} )
        if( IS_DIRECTORY ${_ENTRY} )
            file( TO_NATIVE_PATH ${_ENTRY} _N_ENTRY )
            set( PC_GTK3_INCLUDE_DIRS ${PC_GTK3_INCLUDE_DIRS} ${_N_ENTRY} )
        endif()
    endforeach()
endif()

#message( STATUS "PC_GTK3_INCLUDEDIR: ${PC_GTK3_INCLUDEDIR}" )
#message( STATUS "PC_GTK3_INCLUDE_DIRS: ${PC_GTK3_INCLUDE_DIRS}" )
#message( STATUS "PC_GTK3_LIBRARIES: ${PC_GTK3_LIBRARIES}" )
#message( STATUS "PC_GTK3_LIBRARY_DIRS: ${PC_GTK3_LIBRARY_DIRS}" )
#message( STATUS "PC_GTK3_CFLAGS: ${PC_GTK3_CFLAGS}")
#message( STATUS "PC_GTK3_CFLAGS_OTHER: ${PC_GTK3_CFLAGS_OTHER}" )
#message( STATUS "PC_GTK3_LDFLAGS: ${PC_GTK3_LDFLAGS}" )
#message( STATUS "PC_GTK3_LDFLAGS_OTHER: ${PC_GTK3_LDFLAGS_OTHER}" )

set( GTK3_DEFINITIONS ${PC_GTK3_CFLAGS_OTHER} )

if( NOT PC_GTK3_FOUND )
    find_path( GTK3_INCLUDE_DIR
        NAMES
            "gtk/gtk.h"
        HINTS
            ${GTK3_HINTS}/include
            ${PC_GTK3_INCLUDEDIR}
            ${PC_GTK3_INCLUDE_DIRS}
       PATH_SUFFIXES
            "gtk-3.0"
    )
else()
    set( GTK3_INCLUDE_DIR ${PC_GTK3_INCLUDEDIR} ${PC_GTK3_INCLUDE_DIRS} )
endif()

set( _C 1 )
foreach( _LIB_NAME gtk-3 gtk3 ${PC_GTK3_LIBRARIES} )
    find_library( _LIBRARY_${_C}
        NAMES
           ${_LIB_NAME}
        HINTS
            ${GTK3_HINTS}/lib
            ${PC_GTK3_LIBDIR}
            ${PC_GTK3_LIBRARY_DIRS}
    )
    if( _LIBRARY_${_C} )
        set( GTK3_LIBRARY ${GTK3_LIBRARY} ${_LIBRARY_${_C}} )
    endif()
    math( EXPR _C "${_C} + 1" )
endforeach()

# handle the QUIETLY and REQUIRED arguments and set GTK3_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GTK3 DEFAULT_MSG GTK3_LIBRARY GTK3_INCLUDE_DIR)

if( GTK3_FOUND )
    set( GTK3_LIBRARIES ${GTK3_LIBRARY} )
    set( GTK3_INCLUDE_DIRS ${GTK3_INCLUDE_DIR} )
    if(WIN32)
        set(GTK3_DLL_DIR "${GTK3_HINTS}/bin"
            CACHE PATH "Path to GTK+ 3 DLLS")
        file( GLOB _gtk3_dlls RELATIVE "${GTK3_DLL_DIR}"
            "${GTK3_DLL_DIR}/libgtk-*.dll"
            "${GTK3_DLL_DIR}/libgdk-*.dll"
            "${GTK3_DLL_DIR}/libgdk_pixbuf-*.dll"
            "${GTK3_DLL_DIR}/libatk-*.dll"
            "${GTK3_DLL_DIR}/libpango-*.dll"
            "${GTK3_DLL_DIR}/libpangowin32-*.dll"
            "${GTK3_DLL_DIR}/libcairo-*.dll"
            "${GTK3_DLL_DIR}/libpangocairo-*.dll"
            "${GTK3_DLL_DIR}/libexpat-*.dll"
            "${GTK3_DLL_DIR}/libffi-*.dll"
            "${GTK3_DLL_DIR}/libfontconfig-*.dll"
            "${GTK3_DLL_DIR}/libpangoft2-*.dll"
            "${GTK3_DLL_DIR}/libfreetype-*.dll"
            "${GTK3_DLL_DIR}/libharfbuzz-*.dll"
            "${GTK3_DLL_DIR}/libjasper-*.dll"
            "${GTK3_DLL_DIR}/libjpeg-*.dll"
            "${GTK3_DLL_DIR}/liblzma-*.dll"
            "${GTK3_DLL_DIR}/libpixman-*.dll"
            "${GTK3_DLL_DIR}/libpng??-*.dll"
            "${GTK3_DLL_DIR}/libtiff-*.dll"
            "${GTK3_DLL_DIR}/libxml2-*.dll"
        )
        set(GTK3_DLLS "${_gtk3_dlls}"
            CACHE PATH "List of GTK+ 3 DLLS")
        set(GTK3_ETC_DIR "${GTK3_HINTS}/etc"
            CACHE PATH "Path to GTK+ 3 configuration files")
        set(GTK3_LIB_DIR "${GTK3_HINTS}/lib/gtk-3.0"
            CACHE PATH "Path to additional GTK+ 3 library files")
    endif()
else()
    set( GTK3_LIBRARIES )
    set( GTK3_INCLUDE_DIRS )
    set( GTK3_DLL_DIR )
    set( GTK3_DLLS )
    set( GTK3_ETC_DIR )
    set( GTK3_LIB_DIR )
endif()

mark_as_advanced(GTK3_INCLUDE_DIRS GTK3_LIBRARIES)
