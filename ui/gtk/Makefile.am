# Makefile.am
# Automake file for the GTK interface routines for Wireshark
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

include $(top_srcdir)/Makefile.am.inc
include Makefile_custom.common

# Generated C source files that we want in the distribution.
GENERATED_FILES = \
	wireshark-tap-register.c

# Generated C source files that we don't want in the distribution.
NODIST_GENERATED_FILES =

# Files that generate compileable files
GENERATOR_FILES = \
	main.gresources.xml

WIRESHARK_COMMON_GTK_SRC = \
	about_dlg.c		\
	addr_resolution_dlg.c	\
	bytes_view.c		\
	capture_dlg.c		\
	capture_file_dlg.c	\
	capture_if_dlg.c	\
	capture_info_dlg.c	\
	color_dlg.c		\
	color_edit_dlg.c	\
	color_utils.c		\
	conversation_hastables_dlg.c \
	conversations_table.c	\
	decode_as_dlg.c		\
	dfilter_expr_dlg.c	\
	dissector_tables_dlg.c	\
	dlg_utils.c		\
	drag_and_drop.c 	\
	edit_packet_comment_dlg.c \
	expert_comp_table.c	\
	export_object_dlg.c	\
	export_sslkeys.c	\
	filter_autocomplete.c	\
	file_dlg.c		\
	file_import_dlg.c	\
	fileset_dlg.c		\
	filter_dlg.c		\
	filter_expression_save_dlg.c \
	filter_utils.c		\
	find_dlg.c		\
	firewall_dlg.c		\
	follow_stream.c		\
	font_utils.c		\
	goto_dlg.c		\
	graph_analysis.c 	\
	gtk_iface_monitor.c	\
	gui_stat_util.c		\
	gui_utils.c		\
	help_dlg.c		\
	hostlist_table.c	\
	macros_dlg.c		\
	main.c			\
	main_80211_toolbar.c	\
	main_filter_toolbar.c	\
	main_menubar.c		\
	manual_addr_resolv.c	\
	packet_panes.c		\
	main_statusbar.c	\
	main_titlebar.c		\
	main_toolbar.c		\
	main_welcome.c		\
	packet_history.c	\
	packet_list_store.c	\
	packet_list.c		\
	packet_win.c		\
	pixmap_save.c		\
	plugins_dlg.c		\
	prefs_capture.c		\
	prefs_column.c		\
	prefs_dlg.c		\
	prefs_filter_expressions.c \
	prefs_gui.c		\
	prefs_layout.c		\
	prefs_font_color.c	\
	print_dlg.c		\
	profile_dlg.c		\
	progress_dlg.c		\
	proto_dlg.c		\
	proto_help.c		\
	proto_hier_stats_dlg.c	\
	proto_hier_tree_model.c	\
	proto_tree_model.c	\
	range_utils.c		\
	response_time_delay_table.c \
	rtp_player.c		\
	sctp_byte_graph_dlg.c	\
	sctp_error_dlg.c	\
	sctp_graph_dlg.c	\
	service_response_time_table.c \
	simple_dialog.c		\
	simple_stattable.c	\
	stock_icons.c		\
	summary_dlg.c		\
	supported_protos_dlg.c	\
	tap_param_dlg.c		\
	text_page_utils.c	\
	time_shift_dlg.c	\
	uat_gui.c		\
	webbrowser.c		\
	$(WIRESHARK_CUSTOM_GTK_SRC)

WIRESHARK_TAP_SRC = \
	compare_stat.c		\
	dcerpc_stat.c		\
	expert_comp_dlg.c	\
	export_pdu_dlg.c	\
	flow_graph.c		\
	funnel_stat.c		\
	gsm_map_summary.c	\
	iax2_analysis.c		\
	io_stat.c		\
	lbm_stream_dlg.c	\
	lbm_uimflow_dlg.c	\
	mac_lte_stat_dlg.c	\
	mcast_stream_dlg.c	\
	mtp3_summary.c		\
	rlc_lte_graph.c		\
	rlc_lte_stat_dlg.c	\
	rpc_stat.c		\
	rtp_analysis.c		\
	rtp_stream_dlg.c	\
	sctp_assoc_analyse.c	\
	sctp_chunk_stat.c	\
	sctp_chunk_stat_dlg.c	\
	sctp_stat_dlg.c		\
	stats_tree_stat.c	\
	tcp_graph.c		\
	voip_calls_dlg.c	\
	wlan_stat_dlg.c		\
	$(WIRESHARK_CUSTOM_TAP_SRC)

WIRESHARK_COMMON_GTK_HDRS = \
	about_dlg.h		\
	addr_resolution_dlg.h	\
	bytes_view.h		\
	capture_dlg.h		\
	capture_file_dlg.h	\
	capture_if_dlg.h	\
	cfilter_combo_utils.h	\
	color_dlg.h		\
	color_edit_dlg.h	\
	color_utils.h		\
	conversation_hastables_dlg.h \
	conversations_table.h	\
	decode_as_dlg.h		\
	dfilter_expr_dlg.h	\
	dissector_tables_dlg.h	\
	dlg_utils.h		\
	drag_and_drop.h		\
	edit_packet_comment_dlg.h \
	expert_comp_dlg.h	\
	expert_comp_table.h	\
	export_object_dlg.h	\
	export_pdu_dlg.h	\
	export_sslkeys.h	\
	file_dlg.h		\
	file_import_dlg.h	\
	fileset_dlg.h		\
	filter_autocomplete.h	\
	filter_dlg.h		\
	filter_expression_save_dlg.h \
	filter_utils.h		\
	find_dlg.h		\
	firewall_dlg.h		\
	follow_stream.h		\
	font_utils.h		\
	goto_dlg.h		\
	graph_analysis.h	\
	gtk_iface_monitor.h	\
	gtkglobals.h		\
	gui_stat_menu.h		\
	gui_stat_util.h		\
	gui_utils.h		\
	help_dlg.h		\
	hostlist_table.h	\
	keys.h			\
	lbm_stream_dlg.h	\
	lbm_uimflow_dlg.h	\
	macros_dlg.h		\
	main.h			\
	main_filter_toolbar.h	\
	main_menubar_private.h	\
	main_80211_toolbar.h	\
	menus.h			\
	packet_panes.h		\
	main_statusbar_private.h \
	main_titlebar.h		\
	main_toolbar.h		\
	main_toolbar_private.h	\
	main_welcome.h		\
	main_welcome_private.h	\
	manual_addr_resolv.h	\
	mcast_stream_dlg.h	\
	old-gtk-compat.h	\
	packet_history.h	\
	packet_list_store.h	\
	packet_list.h		\
	packet_win.h		\
	pixmap_save.h		\
	plugins_dlg.h		\
	prefs_capture.h		\
	prefs_column.h		\
	prefs_dlg.h		\
	prefs_filter_expressions.h \
	prefs_gui.h		\
	prefs_layout.h		\
	prefs_font_color.h	\
	profile_dlg.h		\
	proto_dlg.h		\
	proto_help.h		\
	proto_hier_stats_dlg.h	\
	proto_hier_tree_model.h	\
	proto_tree_model.h	\
	range_utils.h		\
	response_time_delay_table.h \
	rtp_player.h		\
	rtp_stream_dlg.h	\
	sctp_stat_gtk.h		\
	service_response_time_table.h \
	simple_stattable.h	\
	time_shift_dlg.h	\
	simple_dialog.h		\
	stock_icons.h		\
	summary_dlg.h		\
	supported_protos_dlg.h	\
	tap_param_dlg.h		\
	text_page_utils.h	\
	uat_gui.h		\
	voip_calls_dlg.h	\
	webbrowser.h		\
	$(WIRESHARK_CUSTOM_HDRS)

if HAVE_GRESOURCE_PIXBUF
NODIST_GENERATED_FILES += \
	wireshark-gresources.h	\
	wireshark-gresources.c
else
BUILD_PIXBUF_CSOURCE = \
	pixbuf-csource.h	\
	pixbuf-csource.c
endif

if HAVE_EXTCAP
WIRESHARK_COMMON_GTK_SRC += extcap_gtk.c
WIRESHARK_COMMON_GTK_HDRS += extcap_gtk.h
endif

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GTK_CFLAGS) \
	$(PORTAUDIO_INCLUDES)

CLEANFILES = \
	libgtkui.a				\
	wireshark-tap-register.c-tmp		\
	wireshark-tap-register-cache.pkl	\
	*~

DISTCLEANFILES = \
	$(NODIST_GENERATED_FILES)

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

EXTRA_DIST = \
	.editorconfig			\
	$(GENERATOR_FILES)		\
	airpcap_dlg.c			\
	airpcap_dlg.h			\
	airpcap_gui_utils.c		\
	airpcap_gui_utils.h		\
	capture_if_details_dlg_win32.c	\
	capture_if_details_dlg_win32.h	\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	main_airpcap_toolbar.c		\
	main_airpcap_toolbar.h		\
	Makefile_custom.common		\
	pixbuf-csource.c		\
	pixbuf-csource.h

BUILT_SOURCES = \
	$(GENERATED_FILES)	\
	$(NODIST_GENERATED_FILES)

noinst_LIBRARIES = libgtkui.a

libgtkui_a_SOURCES = \
	$(WIRESHARK_COMMON_GTK_SRC)	\
	$(WIRESHARK_COMMON_GTK_HDRS)	\
	$(WIRESHARK_TAP_SRC)		\
	$(GENERATED_FILES)

nodist_libgtkui_a_SOURCES = \
	$(NODIST_GENERATED_FILES)	\
	$(BUILD_PIXBUF_CSOURCE)

libgtkui_a_DEPENDENCIES =

#
# Build "wireshark-tap-register.c", which contains a function
# "register_all_tap_listeners()"
# that calls the register routines for all wireshark tap listeners.
#
# We do this by grepping through sources.
#
# Formatting conventions:  The name of the tap_listener_register_*
# routines must start in column zero, or must be preceded only by
# "void " starting in column zero, and must not be inside #if.
#
# The first argument is the directory in which the source files live.
# All subsequent arguments are the files to scan.
#
wireshark-tap-register.c:  $(WIRESHARK_TAP_SRC) Makefile_custom.common $(top_srcdir)/tools/make-tap-reg.py
	@echo Making wireshark-tap-register.c
	@$(PYTHON) $(top_srcdir)/tools/make-tap-reg.py $(srcdir) taps $(WIRESHARK_TAP_SRC)

wireshark-gresources.c: main.gresources.xml $(shell glib-compile-resources --sourcedir=$(top_srcdir) --generate-dependencies $(srcdir)/main.gresources.xml)
	@echo Making $@
	@glib-compile-resources --sourcedir=$(top_srcdir) --target=$@ --generate --manual-register $<

wireshark-gresources.h: main.gresources.xml
	@echo Making $@
	@glib-compile-resources --sourcedir=$(top_srcdir) --target=$@ --generate --manual-register $<

imagedir = $(top_srcdir)/image

pixbuf_csource_data = \
	expert_chat_pb_data				\
	$(imagedir)/toolbar/14x14/x-expert-chat.png	\
	expert_error_pb_data				\
	$(imagedir)/toolbar/14x14/x-expert-error.png	\
	expert_none_pb_data				\
	$(imagedir)/toolbar/14x14/x-expert-none.png	\
	expert_note_pb_data				\
	$(imagedir)/toolbar/14x14/x-expert-note.png	\
	expert_warn_pb_data				\
	$(imagedir)/toolbar/14x14/x-expert-warn.png	\
	expert_ok_pb_data				\
	$(imagedir)/expert_ok.png			\
	capture_comment_add_pb_data			\
	$(imagedir)/capture_comment_add.png		\
	capture_comment_update_pb_data			\
	$(imagedir)/capture_comment_update.png		\
	capture_comment_disabled_pb_data		\
	$(imagedir)/capture_comment_disabled.png	\
	network_bluetooth_pb_data			\
	$(imagedir)/toolbar/network_bluetooth_16.png	\
	network_usb_pb_data				\
	$(imagedir)/toolbar/network_usb_16.png		\
	network_wired_pb_data				\
	$(imagedir)/toolbar/network_wired_16.png	\
	network_wireless_pb_data			\
	$(imagedir)/toolbar/network_wireless_16.png	\
	remote_arrow_pb_data				\
	$(imagedir)/toolbar/remote_arrow_16.png		\
	remote_globe_pb_data				\
	$(imagedir)/toolbar/remote_globe_16.png		\
	remote_sat_pb_data				\
	$(imagedir)/toolbar/remote_sat_16.png		\
	pipe_pb_data					\
	$(imagedir)/toolbar/pipe_16.png			\
	capture_interfaces_16_pb_data			\
	$(imagedir)/toolbar/capture_interfaces_16.png	\
	capture_interfaces_24_pb_data			\
	$(imagedir)/toolbar/capture_interfaces_24.png	\
	gnome_emblem_web_16_pb_data			\
	$(imagedir)/toolbar/gnome_emblem_web_16.png	\
	gnome_emblem_web_24_pb_data			\
	$(imagedir)/toolbar/gnome_emblem_web_24.png	\
	toolbar_wireshark_file_16_pb_data		\
	$(imagedir)/toolbar/16x16/x-capture-file-save.png \
	toolbar_wireshark_file_24_pb_data		\
	$(imagedir)/toolbar/24x24/x-capture-file-save.png \
	capture_options_alt1_16_pb_data			\
	$(imagedir)/toolbar/16x16/x-capture-options.png \
	capture_options_alt1_24_pb_data			\
	$(imagedir)/toolbar/24x24/x-capture-options.png \
	capture_restart_16_pb_data			\
	$(imagedir)/toolbar/16x16/x-capture-restart.png \
	capture_restart_24_pb_data			\
	$(imagedir)/toolbar/24x24/x-capture-restart.png \
	capture_start_16_pb_data			\
	$(imagedir)/toolbar/16x16/x-capture-start.png	\
	capture_start_24_pb_data			\
	$(imagedir)/toolbar/24x24/x-capture-start.png	\
	capture_stop_16_pb_data				\
	$(imagedir)/toolbar/16x16/x-capture-stop.png	\
	capture_stop_24_pb_data				\
	$(imagedir)/toolbar/24x24/x-capture-stop.png	\
	layout_1_pb_data 				\
	$(imagedir)/layout_1.png			\
	layout_2_pb_data				\
	$(imagedir)/layout_2.png			\
	layout_3_pb_data				\
	$(imagedir)/layout_3.png			\
	layout_4_pb_data				\
	$(imagedir)/layout_4.png			\
	layout_5_pb_data				\
	$(imagedir)/layout_5.png			\
	layout_6_pb_data				\
	$(imagedir)/layout_6.png			\
	wsicon_16_pb_data				\
	$(imagedir)/wsicon16.png			\
	wsicon_24_pb_data				\
	$(imagedir)/wsicon24.png			\
	wsicon_32_pb_data				\
	$(imagedir)/wsicon32.png			\
	wsicon_48_pb_data				\
	$(imagedir)/wsicon48.png			\
	wsicon_64_pb_data				\
	$(imagedir)/wsicon64.png			\
	wsiconcap_16_pb_data				\
	$(imagedir)/wsiconcap16.png			\
	wsiconcap_24_pb_data				\
	$(imagedir)/wsiconcap24.png			\
	wsiconcap_32_pb_data				\
	$(imagedir)/wsiconcap32.png			\
	wsiconcap_48_pb_data				\
	$(imagedir)/wsiconcap48.png			\
	wsiconcap_64_pb_data				\
	$(imagedir)/wsiconcap64.png			\
	wssplash_pb_data				\
	$(imagedir)/wssplash.png

pixbuf-csource:
	$(PERL) $(top_srcdir)/tools/make-pixbuf-csource.pl $@ $(pixbuf_csource_data)

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g deprecated-gtk -build \
	-sourcedir=$(srcdir)		\
	$(WIRESHARK_CLEAN_LIBGTKUI_SRC)	\
	capture_if_details_dlg_win32.c

checkapi-todo:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
	-sourcedir=$(srcdir)	\
	$(WIRESHARK_GTK_SRC)	\
	$(WIRESHARK_TAP_SRC)	\
	capture_if_details_dlg_win32.c
