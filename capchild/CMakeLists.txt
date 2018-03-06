# CMakeLists.txt

#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#


set(CAPCHILD_SRC
	capture_ifinfo.c
	capture_sync.c
)

set_source_files_properties(
	${CAPCHILD_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

file(GLOB CAPCHILD_HEADERS capture_session.h)

add_library(capchild STATIC
	${CAPCHILD_SRC}
)

set_target_properties(capchild PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "Libs")

include( UseCheckAPI )
CHECKAPI(
	NAME
	  capchild-base
	SWITCHES
	  -g deprecated-gtk
	SOURCES
	  ${CAPCHILD_SRC}
)
CHECKAPI(
	NAME
	  capchild-todo
	SWITCHES
	  -M -g deprecated-gtk-todo
	SOURCES
	  ${CAPCHILD_SRC}
)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
