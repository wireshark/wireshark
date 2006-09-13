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

# Disable this later. Alternative: "make VERBOSE=1"
set(CMAKE_VERBOSE_MAKEFILE ON)

set(BUILD_SHARED_LIBS ON)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

set(dumpcap_PLATFORM_SRC
	capture-pcap-util-unix.c
)

set(dumpcap_FILES
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

	${dumpcap_PLATFORM_SRC}
)

include_directories(${CMAKE_BINARY_DIR}
	${CMAKE_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/wiretap)

add_definitions(-DHAVE_CONFIG_H -D_U_=\"__attribute__\(\(unused\)\)\")

link_directories(wiretap)

add_executable(dumpcap ${dumpcap_FILES})

option(BUILD_WITH_GLIB2 "Build using gtk2/glib2 instead of gtk/glib" ON)
option(BUILD_WIRESHARK  "Build the GUI version of Wireshark" ON)
option(ENABLE_STATIC	"Build a static version of Wireshark" OFF)

if (BUILD_WITH_GLIB2)
	if (BUILD_WIRESHARK)
		find_package(GTK2 REQUIRED)
		if (GTK2_FOUND)
			message(GTK2_FOUND)
			include_directories(${GTK2_INCLUDE_DIR})
			# set(dumpcap_LIBS ${dumpcap_LIBS} ${GTK2_LIBRARIES})
		endif (GTK2_FOUND)
	endif (BUILD_WIRESHARK)
	find_package(GLIB2 REQUIRED)
	if (GLIB2_FOUND)
		message(GLIB2_FOUND)
		include_directories(${GLIB2_INCLUDE_DIR})
		set(dumpcap_LIBS ${dumpcap_LIBS} ${GLIB2_glib_LIBRARY})
	endif (GLIB2_FOUND)
else (BUILD_WITH_GLIB2)
	if (BUILD_WIRESHARK)
		find_package(GTK REQUIRED)
		if (GTK_FOUND)
			message(GTK_FOUND)
			include_directories(${GTK_INCLUDE_DIR})
			# set(dumpcap_LIBS ${dumpcap_LIBS} ${GTK_LIBRARIES})
		endif (GTK_FOUND)
	endif (BUILD_WIRESHARK)
	find_package(GLIB REQUIRED)
	if (GLIB_FOUND)
		message(GLIB_FOUND)
		include_directories(${GLIB_INCLUDE_DIR})
		set(dumpcap_LIBS ${dumpcap_LIBS} ${GLIB_glib_LIBRARIES})
	endif (GLIB_FOUND)
endif (BUILD_WITH_GLIB2)

set(PACKAGELIST ZLIB PCAP)

foreach(PACKAGE ${PACKAGELIST})
	find_package(${PACKAGE})
	message(${PACKAGE}_FOUND)
	if (${PACKAGE}_FOUND)
		include_directories(${${PACKAGE}_INCLUDE_DIR})
		set(dumpcap_LIBS ${dumpcap_LIBS} ${${PACKAGE}_LIBRARIES})
	endif (${PACKAGE}_FOUND)
endforeach(PACKAGE)

configure_file(${CMAKE_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_BINARY_DIR}/config.h)

target_link_libraries(dumpcap ${dumpcap_LIBS})

