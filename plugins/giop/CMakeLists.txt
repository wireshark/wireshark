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

set(COSNAMING_SRC
	packet-cosnaming.c
)

set(COSEVENTCOMM_SRC
	packet-coseventcomm.c
)

set(CLEAN_FILES
	${COSNAMING_SRC}
	${COSEVENTCOMM_SRC}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(cosnaming ${LINK_MODE_MODULE}
	${COSNAMING_SRC}
)
set_target_properties(cosnaming PROPERTIES PREFIX "")
set_target_properties(cosnaming PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

target_link_libraries(cosnaming epan)

install(TARGETS cosnaming
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

add_library(coseventcomm ${LINK_MODE_MODULE}
	${COSEVENTCOMM_SRC}
)
set_target_properties(coseventcomm PROPERTIES PREFIX "")
set_target_properties(coseventcomm PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

target_link_libraries(coseventcomm epan)

install(TARGETS coseventcomm
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)


