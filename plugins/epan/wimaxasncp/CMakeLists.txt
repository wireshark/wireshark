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
set_module_info(wimaxasncp 0 0 1 0)

add_definitions(
		${LIBXML2_DEFINITIONS}
)

set(DISSECTOR_SRC
	packet-wimaxasncp.c
)

add_wireshark_epan_plugin_library(wimaxasncp
	PLUGIN_LIBS ${LIBXML2_LIBRARIES}
	PLUGIN_INCS ${LIBXML2_INCLUDE_DIRS}
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
