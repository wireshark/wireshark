# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(NONGENERATED_UI_SRC
	alert_box.c
	capture.c
	capture_ui_utils.c
	clopts_common.c
	cmdarg_err.c
	commandline.c
	console.c
	decode_as_utils.c
	dissect_opts.c
	export_object_ui.c
	export_pdu_ui_utils.c
	help_url.c
	failure_message.c
	file_dialog.c
	filter_files.c
	firewall_rules.c
	iface_toolbar.c
	iface_lists.c
	io_graph_item.c
	language.c
	mcast_stream.c
	packet_list_utils.c
	packet_range.c
	persfilepath_opt.c
	preference_utils.c
	profile.c
	proto_hier_stats.c
	recent.c
	rtp_media.c
	rtp_stream.c
	rtp_stream_id.c
	service_response_time.c
	software_update.c
	ssl_key_export.c
	summary.c
	tap_export_pdu.c
	tap-iax2-analysis.c
	tap-rtp-analysis.c
	tap-rtp-common.c
	tap-sctp-analysis.c
	tap-rlc-graph.c
	tap-tcp-stream.c
	text_import.c
	time_shift.c
	traffic_table_ui.c
	util.c
	voip_calls.c
)

# Enables visibility in IDEs
file(GLOB EXTRA_UI_HEADERS
	rtp_media.h
	rtp_stream.h
	rtp_stream_id.h
	tap-iax2-analysis.h
	tap-rtp-analysis.h
)

set(UI_SRC ${NONGENERATED_UI_SRC})

add_lex_files(LEX_FILES UI_SRC
	text_import_scanner.l
)

set_source_files_properties(
	${UI_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)


add_library(ui STATIC ${UI_SRC})

set_target_properties(ui PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "UI"
)

target_link_libraries(ui wsutil caputils)

if (HTML_HELP_COMPILER)
	add_definitions(-DHHC_DIR)
	target_link_libraries(ui Htmlhelp.lib)
endif()

target_include_directories(ui SYSTEM
	PRIVATE
		${WINSPARKLE_INCLUDE_DIRS}
)

add_definitions(-DDOC_DIR="${CMAKE_INSTALL_FULL_DOCDIR}")

CHECKAPI(
	NAME
	  ui-base
	SWITCHES
	SOURCES
	  ${NONGENERATED_UI_SRC}
# Flex files not included due to use of malloc, free etc.
)
CHECKAPI(
	NAME
	  ui-todo
	SWITCHES
	  -M
	SOURCES
	  ${NONGENERATED_UI_SRC}
# Flex files not included due to use of malloc, free etc.
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
