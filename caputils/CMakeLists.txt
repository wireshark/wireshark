# CMakeLists.txt
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


if(UNIX)
	set(PLATFORM_CAPUTILS_SRC
		capture-pcap-util-unix.c
	)
endif()

if(WIN32)
	set(PLATFORM_CAPUTILS_SRC
		capture_win_ifnames.c
		capture-wpcap.c
		capture_wpcap_packet.c
	)
endif()

set(CAPUTILS_SRC
	${PLATFORM_CAPUTILS_SRC}
	capture-pcap-util.c
	iface_monitor.c
	ws80211_utils.c
)

if (AIRPCAP_FOUND)
	set(CAPUTILS_SRC
		${CAPUTILS_SRC}
		airpcap_loader.c
	)
endif()

set(CLEAN_FILES
	${CAPUTILS_SRC}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()


add_library(caputils STATIC
	${CAPUTILS_SRC}
)

set_target_properties(caputils PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "Libs")

CHECKAPI(
	NAME
	  caputils-base
	SWITCHES
	  -g deprecated-gtk
	SOURCES
	  ${CAPUTILS_SRC}
)
CHECKAPI(
	NAME
	  caputils-todo
	SWITCHES
	  -M -g deprecated-gtk-todo
	SOURCES
	  ${CAPUTILS_SRC}
)
