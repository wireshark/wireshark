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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


set(WIRESHARK_GTK_SRC
	about_dlg.c
	airpcap_dlg.c
	airpcap_gui_utils.c
	bytes_view.c
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
	edit_packet_comment_dlg.c
	expert_comp_table.c
	export_object_dlg.c
	export_sslkeys.c
	filter_autocomplete.c
	file_dlg.c
	file_import_dlg.c
	fileset_dlg.c
	filter_dlg.c
	filter_expression_save_dlg.c
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
	gtk_iface_monitor.c
	gui_stat_util.c
	gui_utils.c
	help_dlg.c
	hostlist_table.c
	macros_dlg.c
	main.c
	main_80211_toolbar.c
	main_airpcap_toolbar.c
	main_filter_toolbar.c
	main_menubar.c
	main_statusbar.c
	main_titlebar.c
	main_toolbar.c
	main_welcome.c
	manual_addr_resolv.c
	mcast_stream.c
	packet_history.c
	packet_list_store.c
	packet_list.c
	packet_panes.c
	packet_win.c
	pixmap_save.c
	plugins_dlg.c
	prefs_capture.c
	prefs_column.c
	prefs_dlg.c
	prefs_filter_expressions.c
	prefs_gui.c
	prefs_layout.c
	prefs_stream.c
	print_dlg.c
	profile_dlg.c
	progress_dlg.c
	proto_dlg.c
	proto_help.c
	proto_hier_stats_dlg.c
	proto_hier_tree_model.c
	proto_tree_model.c
	range_utils.c
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
	text_page_utils.c
	time_shift_dlg.c
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
	rlc_lte_graph.c
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

if (NOT ENABLE_GTK3)
	add_definitions(
		# We are only allowed to include gtk/gtk.h, no other files. When
		# violating this with gtk3 the compiler will complain anyway.
		-DGTK_DISABLE_SINGLE_INCLUDES

		# GTK+ 3 removes many implementation details and struct members from its
		# public headers. Make the compiler catch all uses of direct access to
		# struct fields so that you can go through them one by one and replace
		# them with a call to an accessor function instead.
		-DGSEAL_ENABLE

		# To verify that your program does not use any deprecated symbols,
		# you can use defines to remove deprecated symbols from the header files
		# -DGDK_DISABLE_DEPRECATED
		-DGTK_DISABLE_DEPRECATED
	)
endif()

if (WANT_PACKET_EDITOR)
	add_definitions(
		-DWANT_PACKET_EDITOR
	)
endif()

if(WIN32)
	set(PLATFORM_UI_SRC
		capture_if_details_dlg_win32.c
	)
endif()

register_tap_files(wireshark-tap-register.c
	${WIRESHARK_TAP_SRC}
)

add_library(gtkui STATIC
	${WIRESHARK_GTK_SRC}
	${WIRESHARK_TAP_SRC}
	${PLATFORM_UI_SRC}
	wireshark-tap-register.c
)
set_target_properties(gtkui PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

install(
	DIRECTORY
		ui
	DIRECTORY_PERMISSIONS
		OWNER_EXECUTE OWNER_WRITE OWNER_READ
		GROUP_EXECUTE GROUP_READ
		WORLD_EXECUTE WORLD_READ
	DESTINATION
		${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
	PATTERN ".svn" EXCLUDE
)
