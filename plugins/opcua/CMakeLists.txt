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

set(DISSECTOR_SRC
	opcua.c
)

set(DISSECTOR_SUPPORT_SRC
	opcua_transport_layer.c
	opcua_security_layer.c
	opcua_application_layer.c
	opcua_serviceparser.c
	opcua_complextypeparser.c
	opcua_enumparser.c
	opcua_simpletypes.c
	opcua_servicetable.c
	opcua_extensionobjecttable.c
	opcua_hfindeces.c
	opcua_statuscode.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
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

add_library(opcua ${LINK_MODE_MODULE}
	${PLUGIN_FILES}
	plugin.rc
)
set_target_properties(opcua PROPERTIES PREFIX "")
set_target_properties(opcua PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(opcua PROPERTIES FOLDER "Plugins")

target_link_libraries(opcua epan)

install(TARGETS opcua
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

