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

set(DISSECTOR_SRC
	packet-sercosiii.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_dissector_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_library(sercosiii ${LINK_MODE_MODULE}
	${PLUGIN_FILES}
)
set_target_properties(sercosiii PROPERTIES PREFIX "")
set_target_properties(sercosiii PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

target_link_libraries(sercosiii epan)

install(TARGETS sercosiii
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

