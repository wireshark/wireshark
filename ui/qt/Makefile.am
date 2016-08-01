# Makefile.am
# Automake file for the Qt interface routines for Wireshark
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

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS) $(Qt_CFLAGS)

if HAVE_SPEEXDSP
AM_CPPFLAGS += $(SPEEXDSP_CFLAGS)
endif

noinst_LIBRARIES = libqtui.a

include Makefile_custom.common

# Generated header files that we want in the distribution.
GENERATED_HEADER_FILES =

# Generated header files that we don't want in the distribution.
NODIST_GENERATED_HEADER_FILES = \
	ui_about_dialog.h				\
	ui_address_editor_frame.h			\
	ui_bluetooth_att_server_attributes_dialog.h	\
	ui_bluetooth_device_dialog.h			\
	ui_bluetooth_devices_dialog.h			\
	ui_bluetooth_hci_summary_dialog.h		\
	ui_capture_file_properties_dialog.h		\
	ui_capture_interfaces_dialog.h			\
	ui_capture_preferences_frame.h			\
	ui_coloring_rules_dialog.h			\
	ui_column_preferences_frame.h			\
	ui_column_editor_frame.h			\
	ui_compiled_filter_output.h			\
	ui_conversation_hash_tables_dialog.h		\
	ui_decode_as_dialog.h				\
	ui_display_filter_expression_dialog.h		\
	ui_dissector_tables_dialog.h			\
	ui_enabled_protocols_dialog.h			\
	ui_expert_info_dialog.h				\
	ui_export_object_dialog.h			\
	ui_export_pdu_dialog.h				\
	ui_file_set_dialog.h				\
	ui_filter_dialog.h				\
	ui_filter_expression_frame.h			\
	ui_filter_expressions_preferences_frame.h	\
	ui_firewall_rules_dialog.h			\
	ui_follow_stream_dialog.h			\
	ui_font_color_preferences_frame.h		\
	ui_funnel_string_dialog.h			\
	ui_funnel_text_dialog.h				\
	ui_gsm_map_summary_dialog.h			\
	ui_iax2_analysis_dialog.h			\
	ui_import_text_dialog.h				\
	ui_io_graph_dialog.h				\
	ui_layout_preferences_frame.h			\
	ui_lbm_lbtrm_transport_dialog.h			\
	ui_lbm_lbtru_transport_dialog.h			\
	ui_lbm_stream_dialog.h				\
	ui_lbm_uimflow_dialog.h				\
	ui_lte_rlc_graph_dialog.h			\
	ui_main_welcome.h				\
	ui_main_window.h				\
	ui_main_window_preferences_frame.h		\
	ui_manage_interfaces_dialog.h			\
	ui_module_preferences_scroll_area.h		\
	ui_mtp3_summary_dialog.h			\
	ui_overlay_scroll_bar.h				\
	ui_packet_comment_dialog.h			\
	ui_packet_dialog.h				\
	ui_packet_format_group_box.h			\
	ui_packet_range_group_box.h			\
	ui_preference_editor_frame.h			\
	ui_preferences_dialog.h				\
	ui_print_dialog.h				\
	ui_profile_dialog.h				\
	ui_progress_frame.h				\
	ui_protocol_hierarchy_dialog.h			\
	ui_remote_capture_dialog.h			\
	ui_remote_settings_dialog.h			\
	ui_resolved_addresses_dialog.h			\
	ui_rtp_analysis_dialog.h			\
	ui_rtp_player_dialog.h				\
	ui_rtp_stream_dialog.h				\
	ui_sctp_all_assocs_dialog.h			\
	ui_sctp_assoc_analyse_dialog.h			\
	ui_sctp_chunk_statistics_dialog.h		\
	ui_sctp_graph_dialog.h				\
	ui_sctp_graph_arwnd_dialog.h			\
	ui_sctp_graph_byte_dialog.h			\
	ui_search_frame.h				\
	ui_sequence_dialog.h				\
	ui_show_packet_bytes_dialog.h			\
	ui_splash_overlay.h				\
	ui_supported_protocols_dialog.h			\
	ui_tap_parameter_dialog.h			\
	ui_tcp_stream_dialog.h				\
	ui_time_shift_dialog.h				\
	ui_traffic_table_dialog.h			\
	ui_uat_dialog.h					\
	ui_voip_calls_dialog.h				\
	ui_wireless_frame.h

# Generated C source files that we want in the distribution.
GENERATED_C_FILES = \
	wireshark-tap-register.c

# Generated C source files that we don't want in the distribution.
NODIST_GENERATED_C_FILES =

# Generated C++ source files that we want in the distribution.
GENERATED_CPP_FILES =

# Generated C++ source files that we don't want in the distribution.
NODIST_GENERATED_CPP_FILES = \
	$(MOC_SRC)	\
	$(QRC_SRC)

# All the generated files we want in the distribution.
GENERATED_FILES = \
	$(GENERATED_HEADER_FILES)	\
	$(GENERATED_C_FILES)		\
	$(GENERATED_CPP_FILES)

# All the generated files we don't want in the distribution.
NODIST_GENERATED_FILES = \
	$(NODIST_GENERATED_HEADER_FILES)	\
	$(NODIST_GENERATED_C_FILES)		\
	$(NODIST_GENERATED_CPP_FILES)

# Files that generate compileable files
GENERATOR_FILES =

#
# Headers that have to be run through moc.
#
MOC_HDRS = \
	about_dialog.h					\
	accordion_frame.h				\
	address_editor_frame.h				\
	bluetooth_att_server_attributes_dialog.h	\
	bluetooth_device_dialog.h			\
	bluetooth_devices_dialog.h			\
	bluetooth_hci_summary_dialog.h			\
	byte_view_tab.h					\
	byte_view_text.h				\
	capture_file.h					\
	capture_file_dialog.h				\
	capture_file_properties_dialog.h		\
	capture_filter_combo.h				\
	capture_filter_edit.h				\
	capture_filter_syntax_worker.h			\
	capture_info_dialog.h				\
	capture_interfaces_dialog.h			\
	capture_preferences_frame.h			\
	coloring_rules_dialog.h				\
	color_utils.h					\
	column_preferences_frame.h			\
	column_editor_frame.h				\
	compiled_filter_output.h			\
	conversation_colorize_action.h			\
	conversation_dialog.h				\
	conversation_hash_tables_dialog.h		\
	decode_as_dialog.h				\
	display_filter_combo.h				\
	display_filter_edit.h				\
	display_filter_expression_dialog.h		\
	dissector_tables_dialog.h			\
	elided_label.h					\
	enabled_protocols_dialog.h			\
	endpoint_dialog.h				\
	expert_info_dialog.h				\
	export_dissection_dialog.h			\
	export_object_dialog.h				\
	export_pdu_dialog.h				\
	field_filter_edit.h				\
	file_set_dialog.h				\
	filter_action.h					\
	filter_dialog.h					\
	filter_expression_frame.h			\
	filter_expressions_preferences_frame.h		\
	find_line_edit.h				\
	firewall_rules_dialog.h				\
	follow_stream_dialog.h				\
	follow_stream_text.h				\
	font_color_preferences_frame.h			\
	funnel_string_dialog.h				\
	funnel_text_dialog.h				\
	funnel_statistics.h				\
	geometry_state_dialog.h				\
	gsm_map_summary_dialog.h			\
	iax2_analysis_dialog.h				\
	import_text_dialog.h				\
	interface_tree.h				\
	io_graph_dialog.h				\
	label_stack.h					\
	layout_preferences_frame.h			\
	lbm_lbtrm_transport_dialog.h			\
	lbm_lbtru_transport_dialog.h			\
	lbm_stream_dialog.h				\
	lbm_uimflow_dialog.h				\
	lte_mac_statistics_dialog.h			\
	lte_rlc_graph_dialog.h				\
	lte_rlc_statistics_dialog.h			\
	main_status_bar.h				\
	main_welcome.h					\
	main_window.h					\
	main_window_preferences_frame.h			\
	manage_interfaces_dialog.h			\
	module_preferences_scroll_area.h		\
	multicast_statistics_dialog.h			\
	mtp3_summary_dialog.h				\
	overlay_scroll_bar.h				\
	packet_comment_dialog.h				\
	packet_dialog.h					\
	packet_format_group_box.h			\
	packet_list.h					\
	packet_list_model.h				\
	packet_range_group_box.h			\
	percent_bar_delegate.h				\
	preference_editor_frame.h			\
	preferences_dialog.h				\
	print_dialog.h					\
	profile_dialog.h				\
	progress_frame.h				\
	proto_tree.h					\
	protocol_hierarchy_dialog.h			\
	protocol_preferences_menu.h			\
	qcustomplot.h					\
	recent_file_status.h				\
	related_packet_delegate.h			\
	remote_capture_dialog.h				\
	remote_settings_dialog.h			\
	resolved_addresses_dialog.h			\
	response_time_delay_dialog.h			\
	rpc_service_response_time_dialog.h		\
	rtp_analysis_dialog.h				\
	rtp_audio_stream.h				\
	rtp_player_dialog.h				\
	rtp_stream_dialog.h				\
	sctp_all_assocs_dialog.h			\
	sctp_assoc_analyse_dialog.h			\
	search_frame.h					\
	sctp_chunk_statistics_dialog.h			\
	sctp_graph_dialog.h				\
	sctp_graph_arwnd_dialog.h			\
	sctp_graph_byte_dialog.h			\
	search_frame.h					\
	sequence_diagram.h				\
	sequence_dialog.h				\
	service_response_time_dialog.h			\
	show_packet_bytes_dialog.h			\
	simple_dialog.h					\
	simple_statistics_dialog.h			\
	sparkline_delegate.h				\
	splash_overlay.h				\
	stats_tree_dialog.h				\
	stock_icon_tool_button.h			\
	supported_protocols_dialog.h			\
	syntax_line_edit.h				\
	tap_parameter_dialog.h				\
	tcp_stream_dialog.h				\
	time_shift_dialog.h				\
	traffic_table_dialog.h				\
	uat_dialog.h					\
	voip_calls_dialog.h				\
	wireless_frame.h				\
	wireshark_application.h				\
	wireshark_dialog.h				\
	wlan_statistics_dialog.h

#
# .ui files.
#
UI_FILES = \
	about_dialog.ui					\
	address_editor_frame.ui				\
	bluetooth_att_server_attributes_dialog.ui	\
	bluetooth_device_dialog.ui			\
	bluetooth_devices_dialog.ui			\
	bluetooth_hci_summary_dialog.ui			\
	capture_file_properties_dialog.ui 		\
	capture_interfaces_dialog.ui 			\
	capture_preferences_frame.ui			\
	coloring_rules_dialog.ui			\
	column_preferences_frame.ui			\
	column_editor_frame.ui				\
	compiled_filter_output.ui 			\
	conversation_hash_tables_dialog.ui		\
	decode_as_dialog.ui				\
	display_filter_expression_dialog.ui		\
	dissector_tables_dialog.ui			\
	enabled_protocols_dialog.ui			\
	expert_info_dialog.ui				\
	export_object_dialog.ui				\
	export_pdu_dialog.ui				\
	file_set_dialog.ui				\
	filter_dialog.ui				\
	filter_expression_frame.ui			\
	filter_expressions_preferences_frame.ui		\
	firewall_rules_dialog.ui			\
	follow_stream_dialog.ui				\
	font_color_preferences_frame.ui			\
	funnel_string_dialog.ui				\
	funnel_text_dialog.ui				\
	gsm_map_summary_dialog.ui			\
	iax2_analysis_dialog.ui				\
	import_text_dialog.ui				\
	io_graph_dialog.ui				\
	layout_preferences_frame.ui			\
	lbm_lbtrm_transport_dialog.ui			\
	lbm_lbtru_transport_dialog.ui			\
	lbm_stream_dialog.ui				\
	lbm_uimflow_dialog.ui				\
	lte_rlc_graph_dialog.ui				\
	main_welcome.ui					\
	main_window.ui					\
	main_window_preferences_frame.ui		\
	manage_interfaces_dialog.ui			\
	module_preferences_scroll_area.ui		\
	mtp3_summary_dialog.ui				\
	packet_format_group_box.ui			\
	packet_range_group_box.ui			\
	packet_comment_dialog.ui			\
	packet_dialog.ui				\
	preference_editor_frame.ui			\
	preferences_dialog.ui				\
	print_dialog.ui					\
	profile_dialog.ui				\
	progress_frame.ui				\
	protocol_hierarchy_dialog.ui			\
	remote_capture_dialog.ui			\
	remote_settings_dialog.ui			\
	resolved_addresses_dialog.ui			\
	rtp_analysis_dialog.ui				\
	rtp_player_dialog.ui				\
	rtp_stream_dialog.ui				\
	sctp_all_assocs_dialog.ui			\
	sctp_assoc_analyse_dialog.ui			\
	sctp_chunk_statistics_dialog.ui			\
	sctp_graph_dialog.ui				\
	sctp_graph_arwnd_dialog.ui			\
	sctp_graph_byte_dialog.ui			\
	search_frame.ui					\
	sequence_dialog.ui				\
	show_packet_bytes_dialog.ui			\
	splash_overlay.ui				\
	supported_protocols_dialog.ui			\
	tap_parameter_dialog.ui				\
	tcp_stream_dialog.ui				\
	time_shift_dialog.ui				\
	traffic_table_dialog.ui				\
	uat_dialog.ui					\
	voip_calls_dialog.ui				\
	wireless_frame.ui

#
# The .moc.cpp files generated from them.
# We do *not* include these in the distribution; if you have the Qt SDK
# installed, so that you can build Qt-based applications, you have moc
# installed.
#
MOC_SRC = $(MOC_HDRS:.h=.moc.cpp)

#
# .qrc files.
#
# Should QRC_FILES or QRC_SRC depend on QRC_IMAGES?
QRC_FILES = \
	../../image/about.qrc			\
	../../image/languages/languages.qrc	\
	../../image/layout.qrc			\
	../../image/toolbar.qrc			\
	../../image/wsicon.qrc

#
# The .cpp files generated from them.
# We do *not* include these in the distribution; if you have the Qt SDK
# installed, so that you can build Qt-based applications, you have rcc
# installed.
#
QRC_SRC = \
	qrc_about.cpp		\
	qrc_languages.cpp	\
	qrc_layout.cpp		\
	qrc_toolbar.cpp		\
	qrc_wsicon.cpp		\
	qrc_i18n.cpp

#
# .ts files.
# wireshark_en should be pluralonly.
#
TS_FILES = \
	wireshark_de.ts		\
	wireshark_en.ts		\
	wireshark_fr.ts		\
	wireshark_it.ts 	\
	wireshark_ja_JP.ts	\
	wireshark_pl.ts		\
	wireshark_zh_CN.ts

#
# .qm files.
#
QM_FILES = $(TS_FILES:.ts=.qm)

WIRESHARK_QT_SRC = \
	about_dialog.cpp				\
	accordion_frame.cpp				\
	address_editor_frame.cpp			\
	bluetooth_att_server_attributes_dialog.cpp	\
	bluetooth_device_dialog.cpp			\
	bluetooth_devices_dialog.cpp			\
	bluetooth_hci_summary_dialog.cpp		\
	byte_view_tab.cpp				\
	byte_view_text.cpp				\
	capture_file.cpp				\
	capture_file_dialog.cpp				\
	capture_file_properties_dialog.cpp		\
	capture_filter_combo.cpp			\
	capture_filter_edit.cpp				\
	capture_filter_syntax_worker.cpp		\
	capture_info_dialog.cpp				\
	capture_interfaces_dialog.cpp			\
	capture_preferences_frame.cpp			\
	color_utils.cpp					\
	coloring_rules_dialog.cpp			\
	column_preferences_frame.cpp			\
	column_editor_frame.cpp				\
	compiled_filter_output.cpp			\
	conversation_colorize_action.cpp		\
	conversation_dialog.cpp				\
	conversation_hash_tables_dialog.cpp		\
	decode_as_dialog.cpp				\
	display_filter_combo.cpp			\
	display_filter_edit.cpp				\
	display_filter_expression_dialog.cpp		\
	dissector_tables_dialog.cpp			\
	elided_label.cpp				\
	enabled_protocols_dialog.cpp			\
	endpoint_dialog.cpp				\
	export_dissection_dialog.cpp			\
	export_object_dialog.cpp			\
	export_pdu_dialog.cpp				\
	field_filter_edit.cpp				\
	file_set_dialog.cpp				\
	filter_action.cpp				\
	filter_dialog.cpp				\
	filter_expression_frame.cpp			\
	filter_expressions_preferences_frame.cpp	\
	find_line_edit.cpp				\
	firewall_rules_dialog.cpp			\
	follow_stream_dialog.cpp			\
	follow_stream_text.cpp				\
	font_color_preferences_frame.cpp		\
	funnel_string_dialog.cpp			\
	funnel_text_dialog.cpp				\
	geometry_state_dialog.cpp			\
	iax2_analysis_dialog.cpp			\
	import_text_dialog.cpp				\
	interface_tree.cpp				\
	label_stack.cpp					\
	layout_preferences_frame.cpp			\
	lbm_lbtrm_transport_dialog.cpp			\
	lbm_lbtru_transport_dialog.cpp			\
	lbm_stream_dialog.cpp				\
	lbm_uimflow_dialog.cpp				\
	lte_mac_statistics_dialog.cpp			\
	lte_rlc_graph_dialog.cpp			\
	lte_rlc_statistics_dialog.cpp			\
	main_status_bar.cpp				\
	main_welcome.cpp				\
	main_window.cpp					\
	main_window_preferences_frame.cpp		\
	main_window_slots.cpp				\
	manage_interfaces_dialog.cpp			\
	module_preferences_scroll_area.cpp		\
	overlay_scroll_bar.cpp				\
	packet_comment_dialog.cpp			\
	packet_dialog.cpp				\
	packet_format_group_box.cpp			\
	packet_list.cpp					\
	packet_list_model.cpp				\
	packet_list_record.cpp				\
	packet_range_group_box.cpp			\
	percent_bar_delegate.cpp			\
	preference_editor_frame.cpp			\
	preferences_dialog.cpp				\
	print_dialog.cpp				\
	profile_dialog.cpp				\
	progress_frame.cpp				\
	proto_tree.cpp					\
	protocol_hierarchy_dialog.cpp			\
	protocol_preferences_menu.cpp			\
	qcustomplot.cpp					\
	qt_ui_utils.cpp					\
	recent_file_status.cpp				\
	related_packet_delegate.cpp			\
	remote_capture_dialog.cpp			\
	remote_settings_dialog.cpp			\
	resolved_addresses_dialog.cpp			\
	response_time_delay_dialog.cpp			\
	rpc_service_response_time_dialog.cpp		\
	rtp_analysis_dialog.cpp				\
	rtp_audio_stream.cpp				\
	rtp_player_dialog.cpp				\
	rtp_stream_dialog.cpp				\
	sctp_all_assocs_dialog.cpp			\
	sctp_assoc_analyse_dialog.cpp			\
	sctp_chunk_statistics_dialog.cpp		\
	sctp_graph_dialog.cpp				\
	sctp_graph_arwnd_dialog.cpp			\
	sctp_graph_byte_dialog.cpp			\
	search_frame.cpp				\
	sequence_diagram.cpp				\
	sequence_dialog.cpp				\
	service_response_time_dialog.cpp		\
	show_packet_bytes_dialog.cpp			\
	simple_dialog.cpp				\
	simple_statistics_dialog.cpp			\
	sparkline_delegate.cpp				\
	splash_overlay.cpp				\
	stock_icon.cpp					\
	stock_icon_tool_button.cpp			\
	supported_protocols_dialog.cpp			\
	syntax_line_edit.cpp				\
	tap_parameter_dialog.cpp			\
	tcp_stream_dialog.cpp				\
	time_shift_dialog.cpp				\
	traffic_table_dialog.cpp			\
	uat_dialog.cpp					\
	voip_calls_dialog.cpp				\
	wireless_frame.cpp				\
	wireshark_application.cpp			\
	wireshark_dialog.cpp

WIRESHARK_QT_TAP_SRC = \
	expert_info_dialog.cpp			\
	funnel_statistics.cpp			\
	gsm_map_summary_dialog.cpp		\
	io_graph_dialog.cpp			\
	lte_mac_statistics_dialog.cpp		\
	lte_rlc_statistics_dialog.cpp		\
	mtp3_summary_dialog.cpp			\
	multicast_statistics_dialog.cpp		\
	rtp_stream_dialog.cpp			\
	sctp_all_assocs_dialog.cpp		\
	sctp_assoc_analyse_dialog.cpp		\
	stats_tree_dialog.cpp			\
	wlan_statistics_dialog.cpp

noinst_HEADERS = \
	$(MOC_HDRS)		\
	packet_list_record.h	\
	qcustomplot.h		\
	qt_ui_utils.h		\
	stock_icon.h		\
	tango_colors.h

if HAVE_EXTCAP
NODIST_GENERATED_HEADER_FILES += \
	ui_extcap_options_dialog.h

MOC_HDRS += \
	extcap_argument.h		\
	extcap_argument_file.h		\
	extcap_argument_multiselect.h	\
	extcap_options_dialog.h

UI_FILES += \
	extcap_options_dialog.ui

WIRESHARK_QT_SRC += \
	extcap_argument.cpp		\
	extcap_argument_file.cpp	\
	extcap_argument_multiselect.cpp	\
	extcap_options_dialog.cpp
endif

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
wireshark-tap-register.c: $(WIRESHARK_QT_TAP_SRC) $(top_srcdir)/tools/make-tap-reg.py
	@echo Making wireshark-tap-register.c
	@$(PYTHON) $(top_srcdir)/tools/make-tap-reg.py $(srcdir) taps $(WIRESHARK_QT_TAP_SRC)

libqtui_a_SOURCES = \
	$(WIRESHARK_QT_SRC)		\
	$(WIRESHARK_QT_TAP_SRC)		\
	$(GENERATED_C_FILES)		\
	$(GENERATED_CPP_FILES)		\
	$(noinst_HEADERS)		\
	$(GENERATED_HEADER_FILES)

nodist_libqtui_a_SOURCES = \
	$(NODIST_GENERATED_C_FILES)	\
	$(NODIST_GENERATED_CPP_FILES)	\
	$(NODIST_GENERATED_HEADER_FILES)

libqtui_a_DEPENDENCIES =

CLEANFILES = \
	libqtui.a			\
	wireshark-tap-register.c-tmp	\
	wireshark-tap-register-cache.pkl \
	*.moc.cpp			\
	qrc_*.cpp			\
	ui_*.h				\
	*~

DISTCLEANFILES = \
	$(NODIST_GENERATED_FILES)	\
	$(QM_FILES)		\
	i18n.qrc

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)		\
	$(NODIST_GENERATED_FILES)	\
	Makefile.in

AM_V_MOC = $(am__v_MOC_@AM_V@)
am__v_MOC_ = $(am__v_MOC_@AM_DEFAULT_V@)
am__v_MOC_0 = @echo "  MOC     " $@;

AM_V_RCC = $(am__v_RCC_@AM_V@)
am__v_RCC_ = $(am__v_RCC_@AM_DEFAULT_V@)
am__v_RCC_0 = @echo "  RCC     " $@;

AM_V_UIC = $(am__v_UIC_@AM_V@)
am__v_UIC_ = $(am__v_UIC_@AM_DEFAULT_V@)
am__v_UIC_0 = @echo "  UIC     " $@;

AM_V_LRELEASE = $(am__v_LRELEASE_@AM_V@)
am__v_LRELEASE_ = $(am__v_LRELEASE_@AM_DEFAULT_V@)
am__v_LRELEASE_0 = @echo "  LRELEASE  " $@;

#
# For building .moc.cpp files from .h files by running moc,
# building .rcc.cpp files from .qrc files by running rcc,
# and building ui_XXX.h files from .ui files by running uic.
#
SUFFIXES = .moc.cpp

#
# The Qt toolchain uses the naming convention moc_FOO.cpp. Should we do the same?
#moc_%.cpp: %.h
#	$(MOC) $< -o $@
#
.h.moc.cpp:
	$(AM_V_MOC)$(MOC) $(MOC_OPTIONS) -I.. -I../.. -o $@ $<

qrc_about.cpp: ../../image/about.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name about -o $@ $<

qrc_layout.cpp: ../../image/layout.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name layout -o $@ $<

qrc_languages.cpp: ../../image/languages/languages.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name languages -o $@ $<

qrc_i18n.cpp: i18n.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name i18n -o $@ $<

qrc_toolbar.cpp: ../../image/toolbar.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name toolbar -o $@ $<

qrc_wsicon.cpp: ../../image/wsicon.qrc
	$(AM_V_RCC)$(RCC) $(RCC_OPTIONS) -name wsicon -o $@ $<

ui_%.h: %.ui
	$(AM_V_UIC)$(UIC) $< -o $@

wireshark_%.qm: wireshark_%.ts
	$(AM_V_LRELEASE)$(LRELEASE) -silent $< -qm $@

i18n_qresource := $(foreach qm, $(QM_FILES),<file>$(qm)</file>)

i18n.qrc: i18n.qrc.in $(QM_FILES)
	$(AM_V_SED)$(SED) \
		-e 's,@i18n_qresource\@,$(i18n_qresource),' \
		-e 's,> *<file>,>%    <file>,g' \
		< $< | tr '%' '\n' > $@

#
# Explicit dependencies to force the ui_ headers to be built.
# See "Recording Dependencies manually" in the "Built Sources"
# section of the automake documentation:
#
#    https://www.gnu.org/software/automake/manual/automake.html#Sources
#
about_dialog.$(OBJEXT): ui_about_dialog.h

address_editor_frame.$(OBJEXT): ui_address_editor_frame.h

bluetooth_att_server_attributes_dialog.$(OBJEXT): ui_bluetooth_att_server_attributes_dialog.h

bluetooth_devices_dialog.$(OBJEXT): ui_bluetooth_devices_dialog.h

bluetooth_device_dialog.$(OBJEXT): ui_bluetooth_device_dialog.h

bluetooth_hci_summary_dialog.$(OBJEXT): ui_bluetooth_hci_summary_dialog.h

capture_file_properties_dialog.$(OBJEXT): ui_capture_file_properties_dialog.h

capture_interfaces_dialog.$(OBJEXT): ui_capture_interfaces_dialog.h

capture_preferences_frame.$(OBJEXT): ui_capture_preferences_frame.h

coloring_rules_dialog.$(OBJEXT): ui_coloring_rules_dialog.h

column_editor_frame.$(OBJEXT): ui_column_editor_frame.h

column_preferences_frame.$(OBJEXT): ui_column_preferences_frame.h

compiled_filter_output.$(OBJEXT): ui_compiled_filter_output.h

conversation_hash_tables_dialog.$(OBJEXT): ui_conversation_hash_tables_dialog.h

decode_as_dialog.$(OBJEXT): ui_decode_as_dialog.h

display_filter_expression_dialog.$(OBJEXT): ui_display_filter_expression_dialog.h

dissector_tables_dialog.$(OBJEXT): ui_dissector_tables_dialog.h

enabled_protocols_dialog.$(OBJEXT): ui_enabled_protocols_dialog.h

expert_info_dialog.$(OBJEXT): ui_expert_info_dialog.h

export_object_dialog.$(OBJEXT): ui_export_object_dialog.h

export_pdu_dialog.$(OBJEXT): ui_export_pdu_dialog.h

extcap_options_dialog.$(OBJEXT): ui_extcap_options_dialog.h

file_set_dialog.$(OBJEXT): ui_file_set_dialog.h

filter_dialog.$(OBJEXT): ui_filter_dialog.h

filter_expression_frame.$(OBJEXT): ui_filter_expression_frame.h

filter_expressions_preferences_frame.$(OBJEXT): ui_filter_expressions_preferences_frame.h

firewall_rules_dialog.$(OBJEXT): ui_firewall_rules_dialog.h

follow_stream_dialog.$(OBJEXT): ui_follow_stream_dialog.h

font_color_preferences_frame.$(OBJEXT): ui_font_color_preferences_frame.h

funnel_string_dialog.$(OBJEXT): ui_funnel_string_dialog.h

funnel_text_dialog.$(OBJEXT): ui_funnel_text_dialog.h

gsm_map_summary_dialog.$(OBJEXT): ui_gsm_map_summary_dialog.h

iax2_analysis_dialog.$(OBJEXT): ui_iax2_analysis_dialog.h

import_text_dialog.$(OBJEXT): ui_import_text_dialog.h

io_graph_dialog.$(OBJEXT): ui_io_graph_dialog.h

layout_preferences_frame.$(OBJEXT): ui_layout_preferences_frame.h

lbm_lbtrm_transport_dialog.$(OBJEXT): ui_lbm_lbtrm_transport_dialog.h

lbm_lbtru_transport_dialog.$(OBJEXT): ui_lbm_lbtru_transport_dialog.h

lbm_stream_dialog.$(OBJEXT): ui_lbm_stream_dialog.h

lbm_uimflow_dialog.$(OBJEXT): ui_lbm_uimflow_dialog.h

lte_rlc_graph_dialog.$(OBJEXT): ui_lte_rlc_graph_dialog.h

main_welcome.$(OBJEXT): ui_main_welcome.h

main_window.$(OBJEXT): ui_main_window.h

main_window_preferences_frame.$(OBJEXT): ui_main_window_preferences_frame.h

main_window_slots.$(OBJEXT): ui_main_window.h

manage_interfaces_dialog.$(OBJEXT): ui_manage_interfaces_dialog.h

module_preferences_scroll_area.$(OBJEXT): ui_module_preferences_scroll_area.h

mtp3_summary_dialog.$(OBJEXT): ui_mtp3_summary_dialog.h

packet_comment_dialog.$(OBJEXT): ui_packet_comment_dialog.h

packet_dialog.$(OBJEXT): ui_packet_dialog.h

packet_format_group_box.$(OBJEXT): ui_packet_format_group_box.h

packet_range_group_box.$(OBJEXT): ui_packet_range_group_box.h

preference_editor_frame.$(OBJEXT): ui_preference_editor_frame.h

preferences_dialog.$(OBJEXT): ui_preferences_dialog.h

print_dialog.$(OBJEXT): ui_print_dialog.h

progress_frame.$(OBJEXT): ui_progress_frame.h

profile_dialog.$(OBJEXT): ui_profile_dialog.h

protocol_hierarchy_dialog.$(OBJEXT): ui_protocol_hierarchy_dialog.h

remote_capture_dialog.$(OBJEXT): ui_remote_capture_dialog.h

remote_settings_dialog.$(OBJEXT): ui_remote_settings_dialog.h

resolved_addresses_dialog.$(OBJEXT): ui_resolved_addresses_dialog.h

rtp_analysis_dialog.$(OBJEXT): ui_rtp_analysis_dialog.h

rtp_player_dialog.$(OBJEXT): ui_rtp_player_dialog.h

rtp_stream_dialog.$(OBJEXT): ui_rtp_stream_dialog.h

search_frame.$(OBJEXT): ui_search_frame.h

sequence_dialog.$(OBJEXT): ui_sequence_dialog.h

sctp_all_assocs_dialog.$(OBJEXT): ui_sctp_all_assocs_dialog.h

sctp_assoc_analyse_dialog.$(OBJEXT): ui_sctp_assoc_analyse_dialog.h

sctp_chunk_statistics_dialog.$(OBJEXT): ui_sctp_chunk_statistics_dialog.h

sctp_graph_dialog.$(OBJEXT): ui_sctp_graph_dialog.h

sctp_graph_arwnd_dialog.$(OBJEXT): ui_sctp_graph_arwnd_dialog.h

sctp_graph_byte_dialog.$(OBJEXT): ui_sctp_graph_byte_dialog.h

show_packet_bytes_dialog.$(OBJEXT): ui_show_packet_bytes_dialog.h

splash_overlay.$(OBJEXT): ui_splash_overlay.h

supported_protocols_dialog.$(OBJEXT): ui_supported_protocols_dialog.h

tap_parameter_dialog.$(OBJEXT): ui_tap_parameter_dialog.h

tcp_stream_dialog.$(OBJEXT): ui_tcp_stream_dialog.h

time_shift_dialog.$(OBJEXT): ui_time_shift_dialog.h

traffic_table_dialog.$(OBJEXT): ui_traffic_table_dialog.h

uat_dialog.$(OBJEXT): ui_uat_dialog.h

voip_calls_dialog.$(OBJEXT): ui_voip_calls_dialog.h

wireless_frame.$(OBJEXT): ui_wireless_frame.h

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

#checkapi: checkapi-base checkapi-todo

EXTRA_DIST = \
	$(GENERATOR_FILES)		\
	$(UI_FILES)			\
	$(QRC_FILES)			\
	$(TS_FILES)			\
	CMakeLists.txt			\
	doxygen.cfg.in			\
	i18n.qrc.in			\
	Makefile_custom.common		\
	gpl-template.txt
