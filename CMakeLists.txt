# CMakeLists.txt
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

project(wireshark C)

cmake_minimum_required(VERSION 2.6)

subdirs(
  wiretap
  wsutil
)

#Where to find local cmake scripts
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

# Under linux the release mode (CMAKE_BUILD_TYPE=release) defines NDEBUG

# Disable this later. Alternative: "make VERBOSE=1"
set(CMAKE_VERBOSE_MAKEFILE ON)

set(BUILD_SHARED_LIBS ON)

#Defines CMAKE_INSTALL_BINDIR, CMAKE_INSTALL_DATADIR, etc ...
include(CMakeInstallDirs)

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/wiretap
  ${CMAKE_SOURCE_DIR}/wsutil
)

#Where to put libraries
if(NOT LIBRARY_OUTPUT_PATH)
  set(LIBRARY_OUTPUT_PATH ${wireshark_BINARY_DIR}/lib CACHE INTERNAL
       "Single output directory for building all libraries.")
endif()

option(BUILD_wireshark   "Build the GUI version of Wireshark" ON)
option(BUILD_tshark      "Build tshark" ON)
option(BUILD_rawshark    "Build rawshark" ON)
option(BUILD_dumpcap     "Build dumpcap" ON)
option(BUILD_text2pcap   "Build text2pcap" ON)
option(BUILD_mergecap    "Build mergecap" ON)
option(BUILD_editcap     "Build editcap" ON)
option(BUILD_capinfos    "Build capinfos" ON)
option(BUILD_randpkt     "Build randpkt" ON)
option(BUILD_dftest      "Build dftest" ON)
option(ENABLE_STATIC     "Build a static version of Wireshark" OFF)
option(ENABLE_ADNS       "Build with adns support" ON)
option(ENABLE_EXTRA_GCC_CHECKS "Do additional -W checks in GCC" OFF)

if(ENABLE_EXTRA_GCC_CHECKS)
  set(WIRESHARK_EXTRA_GCC_FLAGS -Wcast-qual -Wcast-align -Wbad-function-cast
      -pedantic -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings)
endif()

if(CMAKE_COMPILER_IS_GNUCC)
  add_definitions(
    -DHAVE_CONFIG_H
    -D_U_=__attribute__\(\(unused\)\)
    -Wall -Wpointer-arith -W
    ${WIRESHARK_EXTRA_GCC_FLAGS}
  )
else()
  add_definitions(-DHAVE_CONFIG_H -D_U_=\"\")
endif()

#The minimum package list
if(WIN32)
  set(PACKAGELIST WSWIN32 LEX YACC Perl ${PACKAGELIST})
else()
  set(PACKAGELIST GLIB2 PCAP LEX YACC Perl ${PACKAGELIST})
endif()

#build the gui ?
if(BUILD_wireshark)
  set(PACKAGELIST GTK2 ${PACKAGELIST})
endif()

#Gnu asynchronous dns
if(ENABLE_ADNS)
  set(PACKAGELIST ADNS ${PACKAGELIST})
  set(HAVE_GNU_ADNS 1)
endif()

set(PROGLIST text2pcap mergecap capinfos editcap dumpcap)

#Let's loop the package list
foreach(PACKAGE ${PACKAGELIST})
  find_package(${PACKAGE} REQUIRED)
  message(${PACKAGE}_FOUND)
  if (${PACKAGE}_FOUND)
    set(HAVE_LIB${PACKAGE} "1")
    include_directories(${${PACKAGE}_INCLUDE_DIRS})
    message(STATUS "${PACKAGE} include ${${PACKAGE}_INCLUDE_DIRS}")
    foreach(PROG ${PROGLIST})
#      set(${PROG}_LIBS ${${PROG}_LIBS} ${${PACKAGE}_LIBRARIES})
    endforeach()
    message(STATUS "${PACKAGE} lib ${${PACKAGE}_LIBRARIES}")
  endif()
endforeach()

#packaging
set(CPACK_PACKAGE_NAME wireshark)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "capture packet")
set(CPACK_PACKAGE_VENDOR "wireshark")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "3")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "/usr")
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")

include(ConfigureChecks.cmake)

#Big or little endian ?
include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

set(DATAFILE_DIR "${CMAKE_INSTALL_PREFIX}/share/${CPACK_PACKAGE_NAME}")

#Platform specific
if(UNIX)
  set(WS_VAR_IMPORT "extern")
endif()

if(APPLE)
#TODO verify that APPLE implies HAVE_OS_X_FRAMEWORKS
  set(HAVE_OS_X_FRAMEWORKS 1)
endif()

if(WIN32)
  add_definitions(-DHAVE_WIN32_LIBWIRESHARK_LIB -D_NEED_VAR_IMPORT_)
  set(WS_VAR_IMPORT "__declspec(dllimport) extern")

  # Disable deprecation
  if(MSVC80 OR MSVC90)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE)
  endif()
endif()


configure_file(${CMAKE_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_BINARY_DIR}/config.h)

link_directories(
  wiretap
  wsutil
)

ADD_CUSTOM_COMMAND(
   OUTPUT ${CMAKE_BINARY_DIR}/svnversion.h
   COMMAND ${PERL} ${CMAKE_SOURCE_DIR}/make-version.pl
   ARGS
   ${CMAKE_SOURCE_DIR}
)
SET_SOURCE_FILES_PROPERTIES(${CMAKE_BINARY_DIR}/svnversion.h GENERATED)

if(UNIX)
  set(PLATFORM_SRC
    capture-pcap-util-unix.c
  )
endif()

if(WIN32)
  set(PLATFORM_SRC
    capture-wpcap.c capture_wpcap_packet.c
  )
endif()

if(BUILD_wireshark)
# todo
endif()

if(BUILD_tshark)
# todo
endif()

if(BUILD_rawshark)
# todo
endif()

if(BUILD_randpkt)
# todo
endif()

if(BUILD_dftest)
# todo
endif()

if(BUILD_text2pcap)
  set(text2pcap_LIBS
    wiretap
    wsutil
    ${GLIB2_LIBRARIES}
  )
  set(text2pcap_FILES
    text2pcap.c
  )
  add_lex_files(text2pcap_FILES
    text2pcap-scanner.l
  )
  add_executable(text2pcap ${text2pcap_FILES})
  target_link_libraries(text2pcap ${text2pcap_LIBS})
  install(TARGETS text2pcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_mergecap)
  set(mergecap_LIBS
    wiretap
    wsutil
    ${GLIB2_LIBRARIES}
  )
  set(mergecap_FILES
    mergecap.c
    merge.c
    svnversion.h
  )
  add_executable(mergecap ${mergecap_FILES})
  target_link_libraries(mergecap ${mergecap_LIBS})
  install(TARGETS mergecap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_capinfos)
  set(capinfos_LIBS
    wiretap
    wsutil
    ${GLIB2_LIBRARIES}
  )
  set(capinfos_FILES
    capinfos.c
  )
  add_executable(capinfos ${capinfos_FILES})
  target_link_libraries(capinfos ${capinfos_LIBS})
  install(TARGETS capinfos RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_editcap)
  set(editcap_LIBS
    wiretap
    wsutil
    ${GLIB2_LIBRARIES}
  )
  set(editcap_FILES
    editcap.c
    epan/crypt/crypt-md5.c
    epan/nstime.c
  )
  add_executable(editcap ${editcap_FILES})
  target_link_libraries(editcap ${editcap_LIBS})
  install(TARGETS editcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_dumpcap)
  set(dumpcap_LIBS
    wiretap
    wsutil
    ${GLIB2_LIBRARIES}
    ${PCAP_LIBRARIES}
  )
  set(dumpcap_FILES
	svnversion.h
	capture_opts.c
	capture-pcap-util.c
	capture_stop_conditions.c
	clopts_common.c
	conditions.c
	dumpcap.c
	pcapio.c
	ringbuffer.c
	sync_pipe_write.c
	tempfile.c
	version_info.c
	${PLATFORM_SRC}
  )
  add_executable(dumpcap ${dumpcap_FILES})
  target_link_libraries(dumpcap ${dumpcap_LIBS})
  install(TARGETS dumpcap RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
