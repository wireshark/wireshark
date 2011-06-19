# CMakeLists.txt
#
# $Id$
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#


set(WIRESHARK_GTK_SRC
	about_dlg.c
	airpcap_dlg.c
	airpcap_gui_utils.c
	capture_dlg.c
	capture_file_dlg.c
	capture_if_dlg.c
	capture_info_dlg.c
	cfilter_combo_utils.c
	color_dlg.c
	color_edit_dlg.c
	color_utils.c
	conversations_table.c
	decode_as_ber.c
	decode_as_dcerpc.c
	decode_as_dlg.c
	dfilter_expr_dlg.c
	dissector_tables_dlg.c
	dlg_utils.c
	drag_and_drop.c
	expert_comp_table.c
	export_object.c
	export_object_dicom.c
	export_object_http.c
	export_object_smb.c
	export_sslkeys.c
	filter_autocomplete.c
	file_dlg.c
	file_import_dlg.c
	fileset_dlg.c
	filter_dlg.c
	filter_utils.c
	find_dlg.c
	firewall_dlg.c
	follow_ssl.c
	follow_stream.c
	follow_tcp.c
	follow_udp.c
	font_utils.c
	goto_dlg.c
	graph_analysis.c
	gtkvumeter.c
	gui_stat_util.c
	gui_utils.c
	help_dlg.c
	hostlist_table.c
	macros_dlg.c
	main.c
	main_airpcap_toolbar.c
	main_filter_toolbar.c
	main_proto_draw.c
	main_statusbar.c
	main_toolbar.c
	main_welcome.c
	manual_addr_resolv.c
	mcast_stream.c
	menus.c
	new_packet_list.c
	packet_history.c
	packet_list_store.c
	packet_win.c
	pixmap_save.c
	plugins_dlg.c
	prefs_capture.c
	prefs_column.c
	prefs_dlg.c
	prefs_gui.c
	prefs_layout.c
	prefs_nameres.c
	prefs_print.c
	prefs_protocols.c
	prefs_taps.c
	prefs_stream.c
	print_dlg.c
	profile_dlg.c
	progress_dlg.c
	proto_dlg.c
	proto_help.c
	proto_hier_stats_dlg.c
	range_utils.c
	recent.c
	rtp_player.c
	rtp_stream.c
	sctp_byte_graph_dlg.c
	sctp_error_dlg.c
	sctp_graph_dlg.c
	sctp_stat.c
	service_response_time_table.c
	simple_dialog.c
	stock_icons.c
	summary_dlg.c
	supported_protos_dlg.c
	tap_param_dlg.c
	text_import.c
	text_page_utils.c
	uat_gui.c
	voip_calls.c
	webbrowser.c
)

set(WIRESHARK_TAP_SRC
	afp_stat.c
	ansi_a_stat.c
	ansi_map_stat.c
	bootp_stat.c
	camel_counter.c
	camel_srt.c
	compare_stat.c
	conversations_eth.c
	conversations_fc.c
	conversations_fddi.c
	conversations_ip.c
	conversations_ipv6.c
	conversations_ipx.c
	conversations_jxta.c
	conversations_ncp.c
	conversations_rsvp.c
	conversations_sctp.c
	conversations_tcpip.c
	conversations_tr.c
	conversations_udpip.c
	conversations_usb.c
	conversations_wlan.c
	dcerpc_stat.c
	diameter_stat.c
	expert_comp_dlg.c
	fc_stat.c
	flow_graph.c
	funnel_stat.c
	gsm_a_stat.c
	gsm_map_stat.c
	gsm_map_summary.c
	gtp_stat.c
	h225_counter.c
	h225_ras_srt.c
	hostlist_eth.c
	hostlist_fc.c
	hostlist_fddi.c
	hostlist_ip.c
	hostlist_ipv6.c
	hostlist_ipx.c
	hostlist_jxta.c
	hostlist_ncp.c
	hostlist_rsvp.c
	hostlist_sctp.c
	hostlist_tcpip.c
	hostlist_tr.c
	hostlist_udpip.c
	hostlist_usb.c
	hostlist_wlan.c
	iax2_analysis.c
	io_stat.c
	ldap_stat.c
	mac_lte_stat_dlg.c
	mcast_stream_dlg.c
	megaco_stat.c
	mgcp_stat.c
	mtp3_stat.c
	mtp3_summary.c
	ncp_stat.c
	radius_stat.c
	rlc_lte_stat_dlg.c
	rpc_progs.c
	rpc_stat.c
	rtp_analysis.c
	rtp_stream_dlg.c
	scsi_stat.c
	sctp_assoc_analyse.c
	sctp_chunk_stat.c
	sctp_chunk_stat_dlg.c
	sctp_stat_dlg.c
	sip_stat.c
	smb_stat.c
	smb2_stat.c
	stats_tree_stat.c
	tcp_graph.c
	voip_calls_dlg.c
	wlan_stat_dlg.c
	wsp_stat.c
)

set(CLEAN_FILES
	${WIRESHARK_GTK_SRC}
	${WIRESHARK_TAP_SRC}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

add_lex_files(WIRESHARK_GTK_SRC
	text_import_scanner.l
)

if (UI_MANAGER)
	add_definitions(
		-DMAIN_MENU_USE_UIMANAGER=1
	)
endif()
if (WANT_PACKET_EDITOR)
	add_definitions(
		-DWANT_PACKET_EDITOR=1
	)
endif()

register_tap_files(wireshark-tap-register.c
	${WIRESHARK_TAP_SRC}
)

add_library(ui STATIC
	${WIRESHARK_GTK_SRC}
	${WIRESHARK_TAP_SRC}
	wireshark-tap-register.c
)
set_target_properties(ui PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

#install(TARGETS ui
#	LIBRARY DESTINATION lib
#	RUNTIME DESTINATION lib
#	ARCHIVE DESTINATION lib
#)

