# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(profinet 0 2 4 0)

set(DISSECTOR_SRC
	packet-dcerpc-pn-io.c
	packet-dcom-cba.c
	packet-dcom-cba-acco.c
	packet-pn-dcp.c
	packet-pn-mrp.c
	packet-pn-mrrt.c
	packet-pn-ptcp.c
	packet-pn-rt.c
	packet-pn-rtc-one.c
)

set(DISSECTOR_SUPPORT_SRC
	packet-pn.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

add_plugin_library(profinet epan)

target_link_libraries(profinet epan)

install_plugin(profinet epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  profinet
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_SUPPORT_SRC}
	  ${DISSECTOR_HEADERS}
)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
