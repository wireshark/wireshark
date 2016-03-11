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


set(RANDPKT_CORE_SRC
	randpkt_core.c
)

set(CLEAN_FILES
	${RANDPKT_CORE_SRC}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()

file(GLOB RANDPKT_CORE_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" randpkt_core.h)

add_library(randpkt_core STATIC
	${RANDPKT_CORE_SRC}
)

set_target_properties(randpkt_core PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "Libs")

CHECKAPI(
	NAME
	  randpkt_core-base
	SWITCHES
	  -g deprecated-gtk
	SOURCES
	  ${RANDPKT_CORE_SRC}
	  ${RANDPKT_CORE_HEADERS}
)
CHECKAPI(
	NAME
	  randpkt_core-todo
	SWITCHES
	  -M -g deprecated-gtk-todo
	SOURCES
	  ${RANDPKT_CORE_SRC}
	  ${RANDPKT_CORE_HEADERS}
)
