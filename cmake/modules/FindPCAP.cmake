#
# $Id$
#
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
# - Find pcap
# Find the PCAP includes and library
# http://www.tcpdump.org/
#
# The environment variable PCAPDIR allows to specficy where to find
# libpcap in non standard location.
#
#  PCAP_INCLUDE_DIRS - where to find pcap.h, etc.
#  PCAP_LIBRARIES   - List of libraries when using pcap.
#  PCAP_FOUND       - True if pcap found.


IF(EXISTS $ENV{PCAPDIR})
  FIND_PATH(PCAP_INCLUDE_DIR
    NAMES
    pcap/pcap.h
    pcap.h
    PATHS
      $ENV{PCAPDIR}
    NO_DEFAULT_PATH
  )

  FIND_LIBRARY(PCAP_LIBRARY
    NAMES
      pcap
    PATHS
      $ENV{PCAPDIR}
    NO_DEFAULT_PATH
  )


ELSE(EXISTS $ENV{PCAPDIR})
  FIND_PATH(PCAP_INCLUDE_DIR
    NAMES
    pcap/pcap.h
    pcap.h
  )

  FIND_LIBRARY(PCAP_LIBRARY
    NAMES
      pcap
  )

ENDIF(EXISTS $ENV{PCAPDIR})

SET(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
SET(PCAP_LIBRARIES ${PCAP_LIBRARY})

IF(PCAP_INCLUDE_DIRS)
  MESSAGE(STATUS "Pcap include dirs set to ${PCAP_INCLUDE_DIRS}")
ELSE(PCAP_INCLUDE_DIRS)
  MESSAGE(FATAL " Pcap include dirs cannot be found")
ENDIF(PCAP_INCLUDE_DIRS)

IF(PCAP_LIBRARIES)
  MESSAGE(STATUS "Pcap library set to  ${PCAP_LIBRARIES}")
ELSE(PCAP_LIBRARIES)
  MESSAGE(FATAL "Pcap library cannot be found")
ENDIF(PCAP_LIBRARIES)

#Functions
INCLUDE(CheckFunctionExists)
INCLUDE(CheckVariableExists)
SET(CMAKE_REQUIRED_INCLUDES ${PCAP_INCLUDE_DIRS})
SET(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES})
CHECK_VARIABLE_EXISTS("pcap_version" HAVE_PCAP_VERSION)
CHECK_FUNCTION_EXISTS("pcap_open_dead" HAVE_PCAP_OPEN_DEAD)
CHECK_FUNCTION_EXISTS("pcap_freecode" HAVE_PCAP_FREECODE)
#
# Note: for pcap_breakloop() and pcap_findalldevs(), the autoconf script
# checks for more than just whether the function exists, it also checks
# for whether pcap.h declares it; Mac OS X software/security updates can
# update libpcap without updating the headers.
#
CHECK_FUNCTION_EXISTS("pcap_breakloop" HAVE_PCAP_BREAKLOOP)
CHECK_FUNCTION_EXISTS("pcap_findalldevs" HAVE_PCAP_FINDALLDEVS)
CHECK_FUNCTION_EXISTS("pcap_datalink_val_to_name" HAVE_PCAP_DATALINK_VAL_TO_NAME)
CHECK_FUNCTION_EXISTS("pcap_datalink_name_to_val" HAVE_PCAP_DATALINK_NAME_TO_VAL)
CHECK_FUNCTION_EXISTS("pcap_datalink_val_to_description" HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION)
CHECK_FUNCTION_EXISTS("pcap_list_datalinks" HAVE_PCAP_LIST_DATALINKS)
CHECK_FUNCTION_EXISTS("pcap_set_datalink" HAVE_PCAP_SET_DATALINK)
CHECK_FUNCTION_EXISTS("pcap_lib_version" HAVE_PCAP_LIB_VERSION)
CHECK_FUNCTION_EXISTS("pcap_get_selectable_fd" HAVE_PCAP_GET_SELECTABLE_FD)
CHECK_FUNCTION_EXISTS("pcap_free_datalinks" HAVE_PCAP_FREE_DATALINKS)
# Remote pcap checks
CHECK_FUNCTION_EXISTS("pcap_open" H_PCAP_OPEN)
CHECK_FUNCTION_EXISTS("pcap_findalldevs_ex" H_FINDALLDEVS_EX)
CHECK_FUNCTION_EXISTS("pcap_createsrcstr" H_CREATESRCSTR)
if(H_PCAP_OPEN AND H_FINDALLDEVS_EX AND H_CREATESRCSTR)
  SET(HAVE_PCAP_REMOTE 1)
  SET(HAVE_REMOTE 1)
endif()
# reset vars
SET(CMAKE_REQUIRED_INCLUDES "")
SET(CMAKE_REQUIRED_LIBRARIES "")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PCAP DEFAULT_MSG PCAP_INCLUDE_DIRS PCAP_LIBRARIES)

MARK_AS_ADVANCED(
  PCAP_LIBRARIES
  PCAP_INCLUDE_DIRS
)
