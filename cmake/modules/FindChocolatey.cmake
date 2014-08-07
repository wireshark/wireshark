# FindChocolatey
# ----------
#
# This module looks for Chocolatey

# This code was copied from
# http://cmake.org/gitweb?p=cmake.git;a=blob_plain;f=Modules/FindCygwin.cmake;hb=HEAD
# and modified.
#
# Its toplevel COPYING file starts with:
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

if (WIN32)
  find_path(CHOCOLATEY_BIN_PATH
    choco.exe
    PATHS "C:/ProgramData/chocolatey" "C:/Chocolatey" ENV ChocolateyInstall
    PATH_SUFFIXES bin
    DOC "Chocolatey binary path"
    NO_DEFAULT_PATH
  )

  mark_as_advanced(
    CHOCOLATEY_BIN_PATH
  )
endif ()
