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
	packet-pn-rsi.c
	packet-pn-sxp.c
)

set(DISSECTOR_SUPPORT_SRC
	packet-pn.c
)

add_wireshark_epan_plugin_library(profinet
	PLUGIN_LIBS ${LIBXML2_LIBRARIES}
	PLUGIN_INCS ${LIBXML2_INCLUDE_DIRS}
)

target_compile_definitions(profinet
	PRIVATE
		${LIBXML2_DEFINITIONS}
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
