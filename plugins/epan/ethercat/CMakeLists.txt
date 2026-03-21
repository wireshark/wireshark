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
set_module_info(ethercat 0 1 0 0)

set(DISSECTOR_SRC
	packet-ams.c
	packet-ecatmb.c
	packet-esl.c
	packet-ethercat-datagram.c
	packet-ethercat-frame.c
	packet-ioraw.c
	packet-nv.c
)

add_wireshark_epan_plugin_library(ethercat)

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
