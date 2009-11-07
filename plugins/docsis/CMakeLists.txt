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
	packet-bintrngreq.c
	packet-bpkmattr.c
	packet-bpkmreq.c
	packet-bpkmrsp.c
	packet-intrngreq.c
	packet-dccack.c
	packet-dccreq.c
	packet-dccrsp.c
	packet-dcd.c
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

# todo
# Do I need any of this or is this handled by type MODULE?
# asn1_la_LDFLAGS = -module -avoid-version

add_library(docsis MODULE
	${PLUGIN_FILES}
)

target_link_libraries(docsis epan)

install(TARGETS docsis
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

