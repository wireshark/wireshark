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

set(dumpcap_LIBS wiretap)

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
)

#Where to put libraries
if(NOT LIBRARY_OUTPUT_PATH)
  set(LIBRARY_OUTPUT_PATH ${wireshark_BINARY_DIR}/lib CACHE INTERNAL
       "Single output directory for building all libraries.")
endif(NOT LIBRARY_OUTPUT_PATH)

option(BUILD_WIRESHARK   "Build the GUI version of Wireshark" ON)
option(BUILD_TSHARK      "Build tshark" ON)
option(BUILD_DUMPCAP     "Build dumpcap" ON)
option(ENABLE_STATIC     "Build a static version of Wireshark" OFF)
option(ENABLE_ADNS	     "Build with adns support" ON)
option(ENABLE_DBUS	     "Build with D-Bus support" OFF)
option(ENABLE_DBUS_TEST  "Build with D-Bus unitest support" OFF)
option(ENABLE_EXTRA_GCC_CHECKS "Do additional -W checks in GCC" OFF)

if(ENABLE_EXTRA_GCC_CHECKS)
  set(WIRESHARK_EXTRA_GCC_FLAGS -Wcast-qual -Wcast-align -Wbad-function-cast
      -pedantic -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings)
endif(ENABLE_EXTRA_GCC_CHECKS)

if(CMAKE_COMPILER_IS_GNUCC)
  add_definitions(
    -DHAVE_CONFIG_H
    -D_U_=\"__attribute__\(\(unused\)\)\"
    -Wall -Wpointer-arith -W
    ${WIRESHARK_EXTRA_GCC_FLAGS}
  )
else(CMAKE_COMPILER_IS_GNUCC)
  add_definitions(-DHAVE_CONFIG_H -D_U_=\"\")
endif(CMAKE_COMPILER_IS_GNUCC)

if(BUILD_WIRESHARK OR BUILD_TSHARK OR BUILD_DUMPCAP)
  subdirs(wiretap)
endif(BUILD_WIRESHARK OR BUILD_TSHARK OR BUILD_DUMPCAP)

#The minimum package list
set(PACKAGELIST GLIB2 ZLIB PCAP ${PACKAGELIST})

#build the gui ?
if(BUILD_WIRESHARK)
  set(PACKAGELIST GTK2 ${PACKAGELIST})
endif(BUILD_WIRESHARK)

#Gnu asynchronous dns
if(ENABLE_ADNS)
  set(PACKAGELIST ADNS ${PACKAGELIST})
  set(HAVE_GNU_ADNS 1)
endif(ENABLE_ADNS)

#D-Bus
if(ENABLE_DBUS)
  set(PACKAGELIST DBUS DBUSGLIB ${PACKAGELIST})
  subdirs(dbus)
  set(dumpcap_LIBS ${dumpcap_LIBS} capdbus)
endif(ENABLE_DBUS)

#Let's loop the package list 
foreach(PACKAGE ${PACKAGELIST})
  find_package(${PACKAGE} REQUIRED)
  message(${PACKAGE}_FOUND)
  if (${PACKAGE}_FOUND)
    set(HAVE_LIB${PACKAGE} "1")
    include_directories(${${PACKAGE}_INCLUDE_DIRS})
    message(STATUS "${PACKAGE} include ${${PACKAGE}_INCLUDE_DIRS}")
    set(dumpcap_LIBS ${dumpcap_LIBS} ${${PACKAGE}_LIBRARIES})
    message(STATUS "${PACKAGE} lib ${${PACKAGE}_LIBRARIES}")
  endif (${PACKAGE}_FOUND)
endforeach(PACKAGE)

#packaging
set(CPACK_PACKAGE_NAME wireshark)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "capture packet")
set(CPACK_PACKAGE_VENDOR "wireshark")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "99")
set(CPACK_PACKAGE_VERSION_PATCH "4")
set(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")

set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "/usr")
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")

#check system for includes
include(CheckIncludeFile)
check_include_file("arpa/inet.h"         HAVE_ARPA_INET_H)
check_include_file("arpa/nameser.h"      HAVE_ARPA_NAMESER_H)
check_include_file("direct.h"            HAVE_DIRECT_H)
check_include_file("dirent.h"            HAVE_DIRENT_H)
check_include_file("dlfcn.h"             HAVE_DLFCN_H)
check_include_file("fcntl.h"             HAVE_FCNTL_H)
check_include_file("getopt.h"            NEED_GETOPT_H)
check_include_file("g_ascii_strtoull.h"  NEED_G_ASCII_STRTOULL_H)
check_include_file("inet/aton.h"         NEED_INET_ATON_H)
check_include_file("inttypes.h"          HAVE_INTTYPES_H)
check_include_file("lauxlib.h"           HAVE_LAUXLIB_H)
check_include_file("memory.h"            HAVE_MEMORY_H)
check_include_file("netinet/in.h"        HAVE_NETINET_IN_H)
check_include_file("netdb.h"             HAVE_NETDB_H)
check_include_file("portaudio.h"         HAVE_PORTAUDIO_H)
check_include_file("stdarg.h"            HAVE_STDARG_H)
check_include_file("stddef.h"            HAVE_STDDEF_H)
check_include_file("stdint.h"            HAVE_STDINT_H)
check_include_file("stdlib.h"            HAVE_STDLIB_H)
check_include_file("strerror.h"          NEED_STRERROR_H)
check_include_file("strings.h"           HAVE_STRINGS_H)
check_include_file("string.h"            HAVE_STRING_H)
check_include_file("sys/ioctl.h"         HAVE_SYS_IOCTL_H)
check_include_file("sys/param.h"         HAVE_SYS_PARAM_H)
check_include_file("sys/socket.h"        HAVE_SYS_SOCKET_H)
check_include_file("sys/sockio.h"        HAVE_SYS_SOCKIO_H)
check_include_file("sys/stat.h"          HAVE_SYS_STAT_H)
check_include_file("sys/time.h"          HAVE_SYS_TIME_H)
check_include_file("sys/types.h"         HAVE_SYS_TYPES_H)
check_include_file("sys/utsname.h"       HAVE_SYS_UTSNAME_H)
check_include_file("sys/wait.h"          HAVE_SYS_WAIT_H)
check_include_file("unistd.h"            HAVE_UNISTD_H)

#Functions
include(CheckFunctionExists)
check_function_exists("gethostbyname2"   HAVE_GETHOSTBYNAME2)
check_function_exists("getprotobynumber" HAVE_GETPROTOBYNUMBER)
check_function_exists("iconv"            HAVE_ICONV)
check_function_exists("inet_ntop"        HAVE_INET_NTOP_PROTO)
check_function_exists("issetugid"        HAVE_ISSETUGID) 
check_function_exists("mmap"             HAVE_MMAP)
check_function_exists("mprotect"         HAVE_MPROTECT)
check_function_exists("sysconf"          HAVE_SYSCONF)

#Big or little endian ?
include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

set(DATAFILE_DIR "${CMAKE_INSTALL_PREFIX}/share/${CPACK_PACKAGE_NAME}")

#64 Bit format
include(Check64BitFormat)

check_64bit_format(ll FORMAT_64BIT)
check_64bit_format(L FORMAT_64BIT)
check_64bit_format(q FORMAT_64BIT)
check_64bit_format(I64 FORMAT_64BIT)

if(NOT FORMAT_64BIT)
  message(FATAL " 64 bit format missing")
endif(NOT FORMAT_64BIT)

set(PRIX64 "${FORMAT_64BIT}X")
set(PRIx64 "${FORMAT_64BIT}x")
set(PRId64 "${FORMAT_64BIT}d")
set(PRIo64 "${FORMAT_64BIT}o")
set(PRIu64 "${FORMAT_64BIT}u")

#Platform specific
if(UNIX)
  set(WS_VAR_IMPORT "extern")
endif(UNIX)

if(APPLE)
#TODO verify that APPLE implies HAVE_OS_X_FRAMEWORKS
  set(HAVE_OS_X_FRAMEWORKS 1)
endif(APPLE)

if(WIN32)
  add_definitions(-DHAVE_WIN32_LIBWIRESHARK_LIB -D_NEED_VAR_IMPORT_)
  set(WS_VAR_IMPORT "__declspec(dllimport) extern")
endif(WIN32)


configure_file(${CMAKE_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_BINARY_DIR}/config.h)

link_directories(wiretap)


if(BUILD_DUMPCAP)

  set(DUMPCAP_PLATFORM_SRC 
      capture-pcap-util-unix.c
  )

  set(DUMPCAP_FILES
          capture_opts.c
          capture_loop.c
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
          ${DUMPCAP_PLATFORM_SRC}
  )

  add_executable(dumpcap ${DUMPCAP_FILES})
  target_link_libraries(dumpcap ${dumpcap_LIBS})
  install(TARGETS dumpcap RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

endif(BUILD_DUMPCAP)

