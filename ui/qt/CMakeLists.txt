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

# All .h files which inherit from QObject aka which use the Q_OBJECT macro
# need to go here.
set(WIRESHARK_QT_HEADERS
	about_dialog.h
	bluetooth_att_server_attributes_dialog.h
	accordion_frame.h
	byte_view_tab.h
	byte_view_text.h
	capture_file.h
	capture_file_dialog.h
	capture_file_properties_dialog.h
	capture_filter_combo.h
	capture_filter_edit.h
	capture_filter_syntax_worker.h
	capture_info_dialog.h
	capture_interfaces_dialog.h
	capture_preferences_frame.h
	color_utils.h
	coloring_rules_dialog.h
	column_preferences_frame.h
	column_editor_frame.h
	compiled_filter_output.h
	conversation_dialog.h
	decode_as_dialog.h
	display_filter_combo.h
	display_filter_edit.h
	display_filter_expression_dialog.h
	elided_label.h
	endpoint_dialog.h
	expert_info_dialog.h
	export_dissection_dialog.h
	export_object_dialog.h
	export_pdu_dialog.h
	file_set_dialog.h
	filter_action.h
	filter_dialog.h
	filter_dialog.h
	filter_expressions_preferences_frame.h
	follow_stream_dialog.h
	follow_stream_text.h
	font_color_preferences_frame.h
	import_text_dialog.h
	interface_tree.h
	io_graph_dialog.h
	label_stack.h
	layout_preferences_frame.h
	lbm_lbtrm_transport_dialog.h
	lbm_lbtru_transport_dialog.h
	lbm_stream_dialog.h
	lbm_uimflow_dialog.h
	main_status_bar.h
	main_welcome.h
	main_window.h
	main_window_preferences_frame.h
	manage_interfaces_dialog.h
	module_preferences_scroll_area.h
	packet_comment_dialog.h
	packet_dialog.h
	packet_format_group_box.h
	packet_list.h
	packet_list_model.h
	packet_range_group_box.h
	preferences_dialog.h
	print_dialog.h
	profile_dialog.h
	progress_bar.h
	proto_tree.h
	protocol_hierarchy_dialog.h
	qcustomplot.h
	recent_file_status.h
	related_packet_delegate.h
	rtp_stream_dialog.h
	sctp_all_assocs_dialog.h
	sctp_assoc_analyse_dialog.h
	sctp_chunk_statistics_dialog.h
	sctp_graph_dialog.h
	sctp_graph_arwnd_dialog.h
	sctp_graph_byte_dialog.h
	search_frame.h
	sequence_diagram.h
	sequence_dialog.h
	simple_dialog.h
	splash_overlay.h
	stats_tree_dialog.h
	syntax_line_edit.h
	tap_parameter_dialog.h
	tcp_stream_dialog.h
	time_shift_dialog.h
	traffic_table_dialog.h
	uat_dialog.h
	voip_calls_dialog.h
	wireshark_application.h
	wireshark_dialog.h
)

if(HAVE_PCAP_REMOTE)
	set(WIRESHARK_QT_HEADERS
		${WIRESHARK_QT_HEADERS}
		remote_capture_dialog.h
		remote_settings_dialog.h
	)
endif()

if(ENABLE_EXTCAP)
	set(WIRESHARK_QT_HEADERS
		${WIRESHARK_QT_HEADERS}
		extcap_argument.h
		extcap_argument_file.h
		extcap_options_dialog.h
	)
endif()

file(GLOB EXTRA_QT_HEADERS
	packet_list_record.h
	qt_ui_utils.h
	sparkline_delegate.h
	stock_icon.h
)

set(WIRESHARK_QT_SRC
	about_dialog.cpp
	accordion_frame.cpp
	bluetooth_att_server_attributes_dialog.cpp
	byte_view_tab.cpp
	byte_view_text.cpp
	capture_file.cpp
	capture_file_dialog.cpp
	capture_file_properties_dialog.cpp
	capture_filter_combo.cpp
	capture_filter_edit.cpp
	capture_filter_syntax_worker.cpp
	capture_info_dialog.cpp
	capture_interfaces_dialog.cpp
	capture_preferences_frame.cpp
	color_utils.cpp
	coloring_rules_dialog.cpp
	column_preferences_frame.cpp
	column_editor_frame.cpp
	compiled_filter_output.cpp
	decode_as_dialog.cpp
	display_filter_combo.cpp
	display_filter_edit.cpp
	display_filter_expression_dialog.cpp
	elided_label.cpp
	expert_info_dialog.cpp
	export_dissection_dialog.cpp
	export_object_dialog.cpp
	export_pdu_dialog.cpp
	file_set_dialog.cpp
	filter_action.cpp
	filter_dialog.cpp
	filter_expressions_preferences_frame.cpp
	follow_stream_dialog.cpp
	follow_stream_text.cpp
	font_color_preferences_frame.cpp
	import_text_dialog.cpp
	interface_tree.cpp
	label_stack.cpp
	layout_preferences_frame.cpp
	lbm_lbtrm_transport_dialog.cpp
	lbm_lbtru_transport_dialog.cpp
	lbm_stream_dialog.cpp
	lbm_uimflow_dialog.cpp
	main_status_bar.cpp
	main_welcome.cpp
	main_window.cpp
	main_window_preferences_frame.cpp
	main_window_slots.cpp
	manage_interfaces_dialog.cpp
	module_preferences_scroll_area.cpp
	packet_comment_dialog.cpp
	packet_dialog.cpp
	packet_format_group_box.cpp
	packet_list.cpp
	packet_list_model.cpp
	packet_list_record.cpp
	packet_range_group_box.cpp
	preferences_dialog.cpp
	print_dialog.cpp
	profile_dialog.cpp
	progress_bar.cpp
	proto_tree.cpp
	protocol_hierarchy_dialog.cpp
	qcustomplot.cpp
	qt_ui_utils.cpp
	recent_file_status.cpp
	related_packet_delegate.cpp
	rtp_stream_dialog.cpp
	sctp_all_assocs_dialog.cpp
	sctp_assoc_analyse_dialog.cpp
	sctp_chunk_statistics_dialog.cpp
	sctp_graph_dialog.cpp
	sctp_graph_arwnd_dialog.cpp
	sctp_graph_byte_dialog.cpp
	search_frame.cpp
	sequence_diagram.cpp
	sequence_dialog.cpp
	simple_dialog.cpp
	splash_overlay.cpp
	sparkline_delegate.cpp
	stock_icon.cpp
	syntax_line_edit.cpp
	tap_parameter_dialog.cpp
	tcp_stream_dialog.cpp
	time_shift_dialog.cpp
	traffic_table_dialog.cpp
	uat_dialog.cpp
	voip_calls_dialog.cpp
	wireshark_application.cpp
	wireshark_dialog.cpp
)

if(HAVE_PCAP_REMOTE)
	set(WIRESHARK_QT_SRC
		${WIRESHARK_QT_SRC}
		remote_capture_dialog.cpp
		remote_settings_dialog.cpp
	)
endif()

if(ENABLE_EXTCAP)
	set(WIRESHARK_QT_SRC
		${WIRESHARK_QT_SRC}
		extcap_argument.cpp
		extcap_argument_file.cpp
		extcap_options_dialog.cpp
	)
endif()

set(WIRESHARK_QT_TAP_SRC
	conversation_dialog.cpp
	endpoint_dialog.cpp
	io_graph_dialog.cpp
	stats_tree_dialog.cpp
)

set(WIRESHARK_QT_FILES
	${WIRESHARK_QT_SRC}
	${WIRESHARK_QT_TAP_SRC}
)

set(WIRESHARK_QT_UI
	about_dialog.ui
	bluetooth_att_server_attributes_dialog.ui
	capture_file_properties_dialog.ui
	capture_interfaces_dialog.ui
	capture_preferences_frame.ui
	coloring_rules_dialog.ui
	column_preferences_frame.ui
	column_editor_frame.ui
	compiled_filter_output.ui
	decode_as_dialog.ui
	display_filter_expression_dialog.ui
	expert_info_dialog.ui
	export_object_dialog.ui
	export_pdu_dialog.ui
	file_set_dialog.ui
	filter_dialog.ui
	filter_expressions_preferences_frame.ui
	follow_stream_dialog.ui
	font_color_preferences_frame.ui
	import_text_dialog.ui
	io_graph_dialog.ui
	layout_preferences_frame.ui
	lbm_lbtrm_transport_dialog.ui
	lbm_lbtru_transport_dialog.ui
	lbm_stream_dialog.ui
	lbm_uimflow_dialog.ui
	main_welcome.ui
	main_window.ui
	main_window_preferences_frame.ui
	manage_interfaces_dialog.ui
	module_preferences_scroll_area.ui
	packet_comment_dialog.ui
	packet_dialog.ui
	packet_format_group_box.ui
	packet_range_group_box.ui
	preferences_dialog.ui
	print_dialog.ui
	profile_dialog.ui
	protocol_hierarchy_dialog.ui
	rtp_stream_dialog.ui
	sctp_all_assocs_dialog.ui
	sctp_assoc_analyse_dialog.ui
	sctp_chunk_statistics_dialog.ui
	sctp_graph_dialog.ui
	sctp_graph_arwnd_dialog.ui
	sctp_graph_byte_dialog.ui
	search_frame.ui
	sequence_dialog.ui
	splash_overlay.ui
	tap_parameter_dialog.ui
	tcp_stream_dialog.ui
	time_shift_dialog.ui
	traffic_table_dialog.ui
	uat_dialog.ui
	voip_calls_dialog.ui
)

if(HAVE_PCAP_REMOTE)
	set(WIRESHARK_QT_UI
		${WIRESHARK_QT_UI}
		remote_capture_dialog.ui
		remote_settings_dialog.ui
	)
endif()

if(ENABLE_EXTCAP)
	set(WIRESHARK_QT_UI
		${WIRESHARK_QT_UI}
		extcap_options_dialog.ui
	)
endif()

set(WIRESHARK_QT_QRC
	../../image/about.qrc
	../../image/display_filter.qrc
	../../image/languages/languages.qrc
	../../image/layout.qrc
	../../image/status.qrc
	../../image/toolbar.qrc
	../../image/wsicon.qrc
	i18n.qrc
)

set(WIRESHARK_QT_TS
	wireshark_de.ts
	wireshark_en.ts # lupdate -pluralonly
	wireshark_fr.ts
	wireshark_it.ts
	wireshark_ja_JP.ts
	wireshark_pl.ts
	wireshark_zh_CN.ts
)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
)

if (QT_VERSION EQUAL 5)
	QT5_ADD_TRANSLATION(WIRESHARK_QT_TS_QM ${WIRESHARK_QT_TS})
	QT5_ADD_RESOURCES(WIRESHARK_QT_QRC_SRC ${WIRESHARK_QT_QRC})
	QT5_WRAP_UI(WIRESHARK_QT_UI_SRC ${WIRESHARK_QT_UI})
	# For now, do the moc stuff manually
	QT5_WRAP_CPP(WIRESHARK_QT_MOC_SRC ${WIRESHARK_QT_HEADERS})
	# Starting with cmake 2.8.6, we may also use
	# set(CMAKE_AUTOMOC TRUE)
	# or
	# set_target_properties(${some-source-files} PROPERTIES AUTOMOC TRUE)
else()
	QT4_ADD_TRANSLATION(WIRESHARK_QT_TS_QM ${WIRESHARK_QT_TS})
	QT4_ADD_RESOURCES(WIRESHARK_QT_QRC_SRC ${WIRESHARK_QT_QRC})
	QT4_WRAP_UI(WIRESHARK_QT_UI_SRC ${WIRESHARK_QT_UI})
	# For now, do the moc stuff manually
	QT4_WRAP_CPP(WIRESHARK_QT_MOC_SRC ${WIRESHARK_QT_HEADERS})
	# Starting with cmake 2.8.6, we may also use
	# set(CMAKE_AUTOMOC TRUE)
	# or
	# set_target_properties(${some-source-files} PROPERTIES AUTOMOC TRUE)
endif()

if (WERROR)
	set_source_files_properties(
		${WIRESHARK_QT_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
	# The Qt headers generate a ton of shortening errors on 64-bit systems.
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		set_source_files_properties(
			${WIRESHARK_QT_FILES}
			PROPERTIES
			COMPILE_FLAGS -Wno-shorten-64-to-32
		)
	endif()
endif()

add_definitions(${QT_DEFINITIONS})

register_tap_files(wireshark-tap-register.c
        taps
	${WIRESHARK_QT_TAP_SRC}
)

add_library(qtui STATIC
	${WIRESHARK_QT_SRC}
	${WIRESHARK_QT_TAP_SRC}
	${WIRESHARK_QT_UI_SRC}
	${WIRESHARK_QT_MOC_SRC}
	${WIRESHARK_QT_QRC_SRC}
	${WIRESHARK_QT_TS_QM}
	wireshark-tap-register.c
)
set_target_properties(qtui PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(qtui PROPERTIES FOLDER "UI")
