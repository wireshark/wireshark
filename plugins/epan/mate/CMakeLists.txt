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
set_module_info(mate 1 0 1 0)

set(DISSECTOR_SRC
	packet-mate.c
)

set(DISSECTOR_SUPPORT_SRC
	mate_setup.c
	mate_runtime.c
	mate_util.c
)

add_lemon_files(LEMON_FILES GENERATED_FILES
	mate_grammar.lemon
)
add_lex_files(LEX_FILES GENERATED_FILES
	mate_parser.l
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
	${GENERATED_FILES}
)

#Define dissector headers here to prevent the "default" CheckAPI macro
file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")

add_wireshark_epan_plugin_library(mate)

#"Manually" have to call CheckAPI macro because of the extra files (LEMON_FILES, LEX_FILES) that are not included in the add_wireshark_epan_plugin_library() call.
CHECKAPI(
	NAME
	  mate
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_SUPPORT_SRC}
	  ${DISSECTOR_HEADERS}
# LEX files commented out due to use of malloc, free etc.
#	  ${LEX_FILES}
	  ${LEMON_FILES}
)
