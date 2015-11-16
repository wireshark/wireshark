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
#Redistribution and use in source and binary forms, with or without
#modification, are permitted provided that the following conditions
#are met:
#
#* Redistributions of source code must retain the above copyright
#  notice, this list of conditions and the following disclaimer.
#
#* Redistributions in binary form must reproduce the above copyright
#  notice, this list of conditions and the following disclaimer in the
#  documentation and/or other materials provided with the distribution.
#
#* Neither the names of Kitware, Inc., the Insight Software Consortium,
#  nor the names of their contributors may be used to endorse or promote
#  products derived from this software without specific prior written
#  permission.
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#=============================================================================

if (WIN32)
  find_path(CYGWIN_INSTALL_PATH
    cygwin.bat
    PATH ENV WIRESHARK_CYGWIN_INSTALL_PATH
    "C:/Cygwin"
    "C:/Cygwin64"
    "C:/tools/cygwin"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Cygwin\\setup;rootdir]"
    "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Cygnus Solutions\\Cygwin\\mounts v2\\/;native]"
  )

  if(${CYGWIN_INSTALL_PATH} STREQUAL "CYGWIN_INSTALL_PATH-NOTFOUND")
    message(FATAL_ERROR "Cygwin installation path was not detected. You can set it with WIRESHARK_CYGWIN_INSTALL_PATH environment variable.")
  else()
    mark_as_advanced(
      CYGWIN_INSTALL_PATH
    )
  endif()

endif ()
