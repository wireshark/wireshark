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
	commandline.c
	decode_as_utils.c
	dissect_opts.c
	export_pdu_ui_utils.c
	help_url.c
	failure_message.c
	file_dialog.c
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
	tap_export_pdu.c
	tap-iax2-analysis.c
	tap-rtp-analysis.c
	tap-rtp-common.c
	tap-sctp-analysis.c
	tap-rlc-graph.c
	tap-tcp-stream.c
	text_import.c
	text_import_regex.c
	time_shift.c
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
	${NONGENERATED_UI_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

add_library(ui STATIC ${UI_SRC})

target_link_libraries(ui
	PRIVATE
		wsutil
		wiretap
		${M_LIBRARIES}
)

target_include_directories(ui
	SYSTEM PRIVATE
		${PCAP_INCLUDE_DIRS}
		${WINSPARKLE_INCLUDE_DIRS}
)

add_library(summary STATIC summary.c)

target_link_libraries(summary
	PRIVATE
		wiretap
		epan
		wsutil
		${GCRYPT_LIBRARIES}
	)

target_include_directories(summary
	SYSTEM PRIVATE
		${GCRYPT_INCLUDE_DIRS}
)

set_target_properties(ui summary PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "UI"
)
if(MSVC)
	set_target_properties(ui summary PROPERTIES
		LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}"
	)
endif()

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
