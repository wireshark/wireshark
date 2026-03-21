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
set_module_info(opcua 1 0 0 0)

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
	opcua_keyset.c
)

add_wireshark_epan_plugin_library(opcua
	PLUGIN_LIBS ${GCRYPT_LIBRARIES}
	PLUGIN_INCS ${GCRYPT_INCLUDE_DIRS}
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
