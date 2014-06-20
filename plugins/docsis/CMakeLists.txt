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
	packet-bintrngreq.c
	packet-bpkmattr.c
	packet-bpkmreq.c
	packet-bpkmrsp.c
	packet-cmctrlreq.c
	packet-cmctrlrsp.c
	packet-cmstatus.c
	packet-intrngreq.c
	packet-dbcreq.c
	packet-dbcrsp.c
	packet-dbcack.c
	packet-dccack.c
	packet-dccreq.c
	packet-dccrsp.c
	packet-dcd.c
	packet-dpvreq.c
	packet-dpvrsp.c
	packet-docsis.c
	packet-dsaack.c
	packet-dsareq.c
	packet-dsarsp.c
	packet-dscack.c
	packet-dscreq.c
	packet-dscrsp.c
	packet-dsdreq.c
	packet-dsdrsp.c
	packet-macmgmt.c
	packet-map.c
	packet-mdd.c
	packet-regack.c
	packet-regreq.c
	packet-regreqmp.c
	packet-regrsp.c
	packet-regrspmp.c
	packet-rngreq.c
	packet-rngrsp.c
	packet-sync.c
	packet-tlv.c
	packet-tlv-cmctrl.c
	packet-type29ucd.c
	packet-uccreq.c
	packet-uccrsp.c
	packet-ucd.c
	packet-vendor.c
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

add_library(docsis ${LINK_MODE_MODULE}
	${PLUGIN_FILES}
	plugin.rc
)
set_target_properties(docsis PROPERTIES PREFIX "")
set_target_properties(docsis PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(docsis PROPERTIES FOLDER "Plugins")

target_link_libraries(docsis epan)

install(TARGETS docsis
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

