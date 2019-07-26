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

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

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

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

add_plugin_library(mate epan)

target_link_libraries(mate epan)

install_plugin(mate epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  mate
	SWITCHES
	  --group abort
	  --group termoutput:1 --summary-group termoutput
	  --build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_SUPPORT_SRC}
	  ${DISSECTOR_HEADERS}
# LEX files commented out due to use of malloc, free etc.
#	  ${LEX_FILES}
	  ${LEMON_FILES}
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
