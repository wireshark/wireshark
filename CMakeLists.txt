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

PROJECT(dumpcap C)

SET(dumpcap_LIBS wiretap)

SET(CMAKE_VERBOSE_MAKEFILE ON)
SET(BUILD_SHARED_LIBS ON)
SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

SET(PLATFORM_SRC
	capture-pcap-util-unix.c
)

SET(dumpcap_FILES
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

	${PLATFORM_SRC}
)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/wiretap)

ADD_DEFINITIONS(-DHAVE_CONFIG_H -D_U_=\"__attribute__\(\(unused\)\)\")

LINK_DIRECTORIES(wiretap)

ADD_EXECUTABLE(dumpcap ${dumpcap_FILES})

FIND_PACKAGE(GTK2)
INCLUDE_DIRECTORIES(${GTK2_INCLUDE_DIR})
SET(dumpcap_LIBS ${dumpcap_LIBS} ${GTK2_LIBRARIES})

FIND_PACKAGE(ZLIB)
INCLUDE_DIRECTORIES(${ZLIB_INCLUDE_DIR})
SET(dumpcap_LIBS ${dumpcap_LIBS} ${ZLIB_LIBRARIES})

FIND_PACKAGE(Pcap)
INCLUDE_DIRECTORIES(${PCAP_INCLUDE_DIR})
SET(dumpcap_LIBS ${dumpcap_LIBS} ${PCAP_LIBRARIES})

TARGET_LINK_LIBRARIES(dumpcap ${dumpcap_LIBS})

