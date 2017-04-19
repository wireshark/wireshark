# This code was copied from https://gitlab.kitware.com/cmake/cmake/raw/master/Modules/FindLibXml2.cmake
# and modified to support Wireshark Windows 3rd party packages

#.rst:
# FindLibXml2
# -----------
#
# Try to find the LibXml2 xml processing library
#
# Once done this will define
#
# ::
#
#   LIBXML2_FOUND - System has LibXml2
#   LIBXML2_INCLUDE_DIR - The LibXml2 include directory
#   LIBXML2_LIBRARIES - The libraries needed to use LibXml2
#   LIBXML2_DEFINITIONS - Compiler switches required for using LibXml2
#   LIBXML2_XMLLINT_EXECUTABLE - The XML checking tool xmllint coming with LibXml2
#   LIBXML2_VERSION_STRING - the version of LibXml2 found (since CMake 2.8.8)
#
# :: Included for Wireshark build system
#   LIBXML2_DLL_DIR      - (Windows) Path to the libxml2 DLL.
#   LIBXML2_DLL          - (Windows) Name of the libxml2 DLL.


#=============================================================================
# Copyright 2006-2009 Kitware, Inc.
# Copyright 2006 Alexander Neundorf <neundorf@kde.org>
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

# use pkg-config to get the directories and then use these values
# in the find_path() and find_library() calls
find_package(PkgConfig QUIET)
PKG_CHECK_MODULES(PC_LIBXML QUIET libxml-2.0)
set(LIBXML2_DEFINITIONS ${PC_LIBXML_CFLAGS_OTHER})

INCLUDE(FindWSWinLibs)
FindWSWinLibs("libxml2-.*" "LIBXML2_HINTS")

find_path(LIBXML2_INCLUDE_DIR NAMES libxml/xpath.h
   HINTS
   ${PC_LIBXML_INCLUDEDIR}
   ${PC_LIBXML_INCLUDE_DIRS}
   "${LIBXML2_HINTS}/include"
   PATH_SUFFIXES libxml2
   )

find_library(LIBXML2_LIBRARIES NAMES xml2 libxml2 libxml2-2
   HINTS
   ${PC_LIBXML_LIBDIR}
   ${PC_LIBXML_LIBRARY_DIRS}
   "${LIBXML2_HINTS}/lib"
   )

find_program(LIBXML2_XMLLINT_EXECUTABLE xmllint
   HINTS
   "${LIBXML2_HINTS}/bin"
   )
# for backwards compat. with KDE 4.0.x:
set(XMLLINT_EXECUTABLE "${LIBXML2_XMLLINT_EXECUTABLE}")

if(PC_LIBXML_VERSION)
    set(LIBXML2_VERSION_STRING ${PC_LIBXML_VERSION})
elseif(LIBXML2_INCLUDE_DIR AND EXISTS "${LIBXML2_INCLUDE_DIR}/libxml/xmlversion.h")
    file(STRINGS "${LIBXML2_INCLUDE_DIR}/libxml/xmlversion.h" libxml2_version_str
         REGEX "^#define[\t ]+LIBXML_DOTTED_VERSION[\t ]+\".*\"")

    string(REGEX REPLACE "^#define[\t ]+LIBXML_DOTTED_VERSION[\t ]+\"([^\"]*)\".*" "\\1"
           LIBXML2_VERSION_STRING "${libxml2_version_str}")
    unset(libxml2_version_str)
endif()

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibXml2
                                  REQUIRED_VARS LIBXML2_LIBRARIES LIBXML2_INCLUDE_DIR
                                  VERSION_VAR LIBXML2_VERSION_STRING)

# Included for Wireshark build system. If libxml2 was found, include direct
# paths to the DLLs for windows
if(WIN32)
  if(LIBXML2_FOUND)
    set ( LIBXML2_DLL_DIR "${LIBXML2_HINTS}/bin"
      CACHE PATH "Path to Libxml2 DLL"
    )
    file( GLOB _libxml2_dll RELATIVE "${LIBXML2_DLL_DIR}"
      "${LIBXML2_DLL_DIR}/libxml2-*.dll"
    )
    set ( LIBXML2_DLL ${_libxml2_dll}
      # We're storing filenames only. Should we use STRING instead?
      CACHE FILEPATH "Libxml2 DLL file name"
    )
    mark_as_advanced( LIBXML2_DLL_DIR LIBXML2_DLL )
  else()
    set( LIBXML2_LIBRARIES )
    set( LIBXML2_DLL_DIR )
    set( LIBXML2_DLL )
  endif()
endif()

mark_as_advanced(LIBXML2_INCLUDE_DIR LIBXML2_LIBRARIES LIBXML2_XMLLINT_EXECUTABLE)
