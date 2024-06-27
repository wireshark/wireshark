# - Find zlib-ng
#
# Find the native ZLIBNG includes and library.
# Once done this will define
#
#  ZLIBNG_INCLUDE_DIRS   - where to find zlib-ng.h, etc.
#  ZLIBNG_LIBRARIES      - List of libraries when using zlib-ng.
#  ZLIBNG_FOUND          - True if zlib-ng found.
#  ZLIBNG_DLL_DIR        - (Windows) Path to the zlib-ng DLL.
#  ZLIBNG_DLL            - (Windows) Name of the zlib-ng DLL.
#  ZLIBNG_PDB            - (Windows) Name of the zlib-ng PDB.
#
#  ZLIBNG_VERSION_STRING - The version of zlib-ng found (x.y.z)
#  ZLIBNG_VERSION_MAJOR  - The major version of zlib-ng
#  ZLIBNG_VERSION_MINOR  - The minor version of zlib-ng
#  ZLIBNG_VERSION_PATCH  - The patch version of zlib-ng
#  ZLIBNG_VERSION_TWEAK  - The tweak version of zlib-ng
#
# The following variable are provided for backward compatibility
#
#  ZLIBNG_MAJOR_VERSION  - The major version of zlib-ng
#  ZLIBNG_MINOR_VERSION  - The minor version of zlib-ng
#  ZLIBNG_PATCH_VERSION  - The patch version of zlib-ng

#=============================================================================
# Copyright 2001-2009 Kitware, Inc.
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
# Zlib is included with GLib2
FindWSWinLibs( "zlib-ng-" "ZLIBNG_HINTS" )

if (NOT USE_REPOSITORY) # else we'll find Strawberry Perl's pkgconfig
    find_package(PkgConfig)
    pkg_search_module(ZLIBNG zlib-ng)
endif()

FIND_PATH(ZLIBNG_INCLUDE_DIR
    NAMES
        zlib-ng.h
    HINTS
        ${ZLIBNG_INCLUDEDIR}
        ${ZLIBNG_HINTS}/include
    /usr/include
    /usr/local/include
)

SET(ZLIBNG_NAMES z-ng zlib-ng libz-ng.a)
FIND_LIBRARY(ZLIBNG_LIBRARY
    NAMES
        ${ZLIBNG_NAMES}
    HINTS
        ${ZLIBNG_LIBDIR}
        ${ZLIBNG_HINTS}/lib
      PATHS
      /usr/lib
      /usr/local/lib
)

MARK_AS_ADVANCED(ZLIBNG_LIBRARY ZLIBNG_INCLUDE_DIR)

# handle the QUIETLY and REQUIRED arguments and set ZLIBNG_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ZLIBNG REQUIRED_VARS ZLIBNG_LIBRARY ZLIBNG_INCLUDE_DIR
                                       VERSION_VAR ZLIBNG_VERSION_STRING)

if(ZLIBNG_FOUND)
    IF(ZLIBNG_INCLUDE_DIR AND EXISTS "${ZLIBNG_INCLUDE_DIR}/zlib-ng.h")
        FILE(STRINGS "${ZLIBNG_INCLUDE_DIR}/zlib-ng.h" ZLIBNG_H REGEX "^#define ZLIBNG_VERSION \"[^\"]*\"$")

        STRING(REGEX REPLACE "^.*ZLIBNG_VERSION \"([0-9]+).*$" "\\1" ZLIBNG_VERSION_MAJOR "${ZLIBNG_H}")
        STRING(REGEX REPLACE "^.*ZLIBNG_VERSION \"[0-9]+\\.([0-9]+).*$" "\\1" ZLIBNG_VERSION_MINOR  "${ZLIBNG_H}")
        STRING(REGEX REPLACE "^.*ZLIBNG_VERSION \"[0-9]+\\.[0-9]+\\.([0-9]+).*$" "\\1" ZLIBNG_VERSION_PATCH "${ZLIBNG_H}")
        SET(ZLIBNG_VERSION_STRING "${ZLIBNG_VERSION_MAJOR}.${ZLIBNG_VERSION_MINOR}.${ZLIBNG_VERSION_PATCH}")

        # only append a TWEAK version if it exists:
        SET(ZLIBNG_VERSION_TWEAK "")
        IF( "${ZLIBNG_H}" MATCHES "^.*ZLIBNG_VERSION \"[0-9]+\\.[0-9]+\\.[0-9]+\\.([0-9]+).*$")
            SET(ZLIBNG_VERSION_TWEAK "${CMAKE_MATCH_1}")
            SET(ZLIBNG_VERSION_STRING "${ZLIBNG_VERSION_STRING}.${ZLIBNG_VERSION_TWEAK}")
        ENDIF( "${ZLIBNG_H}" MATCHES "^.*ZLIBNG_VERSION \"[0-9]+\\.[0-9]+\\.[0-9]+\\.([0-9]+).*$")

        SET(ZLIBNG_MAJOR_VERSION "${ZLIBNG_VERSION_MAJOR}")
        SET(ZLIBNG_MINOR_VERSION "${ZLIBNG_VERSION_MINOR}")
        SET(ZLIBNG_PATCH_VERSION "${ZLIBNG_VERSION_PATCH}")
    ENDIF()
        INCLUDE(CMakePushCheckState)
        INCLUDE(CheckFunctionExists)
        CMAKE_PUSH_CHECK_STATE()
        set(CMAKE_REQUIRED_INCLUDES ${ZLIBNG_INCLUDE_DIR})
        set(CMAKE_REQUIRED_LIBRARIES ${ZLIBNG_LIBRARY})
        #
        # Check for inflate() in zlib, to make sure the zlib library is
        # usable.
        #
        # For example, on at least some versions of Fedora, if you have a
        # 64-bit machine, have both the 32-bit and 64-bit versions of the
        # run-time zlib package installed, and have only the *32-bit*
        # version of the zlib development package installed, it'll find the
        # header, and think it can use zlib, and will use it in subsequent
        # tests, but it'll try and link 64-bit test programs with the 32-bit
        # library, causing those tests to falsely fail.  Hilarity ensues.
        #
        CHECK_FUNCTION_EXISTS("zng_gzopen" WITH_GZFILEOP)
        IF(NOT WITH_GZFILEOP)
            MESSAGE(FATAL_ERROR "zlib-ng.h found but linking with -lz failed to find zng_gzopen();")
        ENDIF()
        # reset
        CMAKE_POP_CHECK_STATE()

    AddWSWinDLL(ZLIBNG ZLIBNG_HINTS "zlib-ng*")
    SET(ZLIBNG_INCLUDE_DIRS ${ZLIBNG_INCLUDE_DIR})
    SET(ZLIBNG_LIBRARIES ${ZLIBNG_LIBRARY})
ELSE()
    SET(ZLIBNG_INCLUDE_DIRS )
    SET(ZLIBNG_LIBRARIES )
    SET(ZLIBNG_DLL_DIR )
    SET(ZLIBNG_DLL )
    SET(ZLIBNG_PDB )
ENDIF()
