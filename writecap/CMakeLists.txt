# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(WRITECAP_SRC
	pcapio.c
)

set_source_files_properties(
	${WRITECAP_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)


add_library(writecap STATIC
	${WRITECAP_SRC}
)

set_target_properties(writecap PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "Libs"
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
