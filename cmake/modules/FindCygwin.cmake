#.rst:
# FindCygwin
# ----------
#
# this module looks for Cygwin

# This code was copied from
# http://cmake.org/gitweb?p=cmake.git;a=blob_plain;f=Modules/FindCygwin.cmake;hb=HEAD
# and modified so as to check C:\Cygwin64 and the WIRESHARK_CYGWIN_INSTALL_PATH
# environment variable

#=============================================================================
#CMake - Cross Platform Makefile Generator
#Copyright 2000-2015 Kitware, Inc.
#Copyright 2000-2011 Insight Software Consortium
#All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#=============================================================================

if (WIN32)
  find_path(CYGWIN_INSTALL_PATH
    NAMES cygwin.bat
    PATHS
      ENV WIRESHARK_CYGWIN_INSTALL_PATH
      "C:/Cygwin"
      "C:/Cygwin64"
      "C:/tools/cygwin"
      "C:/tools/cygwin64"
      "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Cygwin\\setup;rootdir]"
      "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Cygnus Solutions\\Cygwin\\mounts v2\\/;native]"
  )

  if(NOT CYGWIN_INSTALL_PATH)
    if(WIRESHARK_CYGWIN_INSTALL_PATH)
      message(FATAL_ERROR "WIRESHARK_CYGWIN_INSTALL_PATH was specified, but Cygwin was not found.")
    else()
      message(WARNING "Cygwin installation path was not detected. You can set it with WIRESHARK_CYGWIN_INSTALL_PATH environment variable.")
    endif()
  endif()

  mark_as_advanced(
    CYGWIN_INSTALL_PATH
  )
endif ()
