# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


set(COMMON_UI_SRC
	alert_box.c
	capture.c
	capture_ui_utils.c
	commandline.c
	console.c
	decode_as_utils.c
	export_object.c
	export_object_dicom.c
	export_object_http.c
	export_object_smb.c
	export_object_tftp.c
	export_pdu_ui_utils.c
	help_url.c
	firewall_rules.c
	iface_lists.c
	io_graph_item.c
	language.c
	mcast_stream.c
	packet_list_utils.c
	persfilepath_opt.c
	preference_utils.c
	profile.c
	proto_hier_stats.c
	recent.c
	rtp_media.c
	rtp_stream.c
	service_response_time.c
	software_update.c
	ssl_key_export.c
	tap_export_pdu.c
	tap-iax2-analysis.c
	tap-rtp-common.c
	tap-sctp-analysis.c
	tap-sequence-analysis.c
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
	tap-iax2-analysis.h
	tap-rtp-analysis.h
)

add_lex_files(LEX_FILES GENERATED_FILES
	text_import_scanner.l
)

set(CLEAN_FILES
	${COMMON_UI_SRC}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()


add_library(ui STATIC
	${COMMON_UI_SRC}
	${GENERATED_FILES}
)

set_target_properties(ui PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(ui PROPERTIES FOLDER "UI")

CHECKAPI(
	NAME
	  ui-base
	SWITCHES
	  -g deprecated-gtk
	SOURCES
	  ${COMMON_UI_SRC}
# LEX files commented out due to use of malloc, free etc.
#	  ${LEX_FILES}
)
CHECKAPI(
	NAME
	  ui-todo
	SWITCHES
	  -M -g deprecated-gtk-todo
	SOURCES
	  ${COMMON_UI_SRC}
# LEX files commented out due to use of malloc, free etc.
#	  ${LEX_FILES}
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
