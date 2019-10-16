# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#


set(RANDPKT_CORE_SRC
	randpkt_core.c
)

set_source_files_properties(
	${RANDPKT_CORE_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

file(GLOB RANDPKT_CORE_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" randpkt_core.h)

add_library(randpkt_core STATIC
	${RANDPKT_CORE_SRC}
)

set_target_properties(randpkt_core PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "Libs")

target_link_libraries(randpkt_core PUBLIC ui)

CHECKAPI(
	NAME
	  randpkt_core-base
	SWITCHES
	SOURCES
	  ${RANDPKT_CORE_SRC}
	  ${RANDPKT_CORE_HEADERS}
)
CHECKAPI(
	NAME
	  randpkt_core-todo
	SWITCHES
	  -M
	SOURCES
	  ${RANDPKT_CORE_SRC}
	  ${RANDPKT_CORE_HEADERS}
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
