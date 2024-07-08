# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

if(USE_qt6)
  set(qtver "6")
else()
  set(qtver "5")
endif()

ADD_CUSTOM_CMAKE_INCLUDE()

set(WIRESHARK_WIDGET_HEADERS
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/additional_toolbar.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/apply_line_edit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/byte_view_text.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/capture_filter_combo.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/capture_filter_edit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/clickable_label.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/copy_from_profile_button.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/detachable_tabwidget.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/display_filter_combo.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/display_filter_edit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/dissector_syntax_line_edit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/dissector_tables_view.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/drag_drop_toolbar.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/drag_label.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/editor_file_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/elided_label.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/expert_info_view.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/field_filter_edit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/filter_expression_toolbar.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/find_line_edit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/follow_stream_text.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/interface_toolbar_lineedit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/label_stack.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/overlay_scroll_bar.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/packet_list_header.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/path_selection_edit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/pref_module_view.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/profile_tree_view.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/qcp_axis_ticker_elided.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/qcp_axis_ticker_si.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/qcp_string_legend_item.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/range_syntax_lineedit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/resize_header_view.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/resolved_addresses_view.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/rowmove_tree_view.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/splash_overlay.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/stock_icon_tool_button.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/syntax_line_edit.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/wireless_timeline.h # Required by PacketListModel
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/tabnav_tree_view.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/traffic_tab.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/traffic_tree.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/traffic_types_list.h
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/wireshark_file_dialog.h
)

set (LOGRAY_WIDGET_HEADERS ${WIRESHARK_WIDGET_HEADERS})

set(WIRESHARK_3RD_PARTY_WIDGET_HEADERS
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/qcustomplot.h
)

set (LOGRAY_3RD_PARTY_WIDGET_HEADERS ${WIRESHARK_3RD_PARTY_WIDGET_HEADERS})

set(WIRESHARK_MANAGER_HEADERS
	${CMAKE_SOURCE_DIR}/ui/qt/manager/preference_manager.h
	${CMAKE_SOURCE_DIR}/ui/qt/manager/wireshark_preference.h
)

set (LOGRAY_MANAGER_HEADERS ${WIRESHARK_MANAGER_HEADERS})

set(WIRESHARK_UTILS_HEADERS
	${CMAKE_SOURCE_DIR}/ui/qt/utils/color_utils.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/data_printer.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/field_information.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/frame_information.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/idata_printable.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/profile_switcher.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/proto_node.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/qt_ui_utils.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/stock_icon.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/tango_colors.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/variant_pointer.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/wireshark_mime_data.h
	${CMAKE_SOURCE_DIR}/ui/qt/utils/wireshark_zip_helper.h
)

set (LOGRAY_UTILS_HEADERS ${WIRESHARK_UTILS_HEADERS})

set(WIRESHARK_MODEL_HEADERS
	${CMAKE_SOURCE_DIR}/ui/qt/models/astringlist_list_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/atap_data_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/cache_proxy_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/coloring_rules_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/coloring_rules_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/column_list_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/decode_as_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/decode_as_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/dissector_tables_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/enabled_protocols_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/expert_info_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/expert_info_proxy_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/fileset_entry_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/filter_list_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/info_proxy_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/interface_sort_filter_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/interface_tree_cache_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/interface_tree_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/numeric_value_chooser_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/packet_list_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/packet_list_record.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/path_selection_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/percent_bar_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/pref_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/pref_models.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/profile_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/proto_tree_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/related_packet_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/resolved_addresses_models.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/sparkline_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/supported_protocols_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/timeline_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/tree_model_helpers.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/uat_delegate.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/uat_model.h
	${CMAKE_SOURCE_DIR}/ui/qt/models/url_link_delegate.h
)

set (LOGRAY_MODEL_HEADERS ${WIRESHARK_MODEL_HEADERS})

# All .h files which inherit from QObject aka which use the Q_OBJECT macro
# need to go here.
set(WIRESHARK_QT_HEADERS
	${CMAKE_SOURCE_DIR}/ui/qt/about_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/accordion_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/address_editor_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/byte_view_tab.h
	${CMAKE_SOURCE_DIR}/ui/qt/capture_comment_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/capture_file_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/capture_file_properties_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/capture_file.h
	${CMAKE_SOURCE_DIR}/ui/qt/capture_filter_syntax_worker.h
	${CMAKE_SOURCE_DIR}/ui/qt/capture_options_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/capture_preferences_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/coloring_rules_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/column_editor_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/column_preferences_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/compiled_filter_output.h
	${CMAKE_SOURCE_DIR}/ui/qt/conversation_colorize_action.h
	${CMAKE_SOURCE_DIR}/ui/qt/conversation_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/conversation_hash_tables_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/decode_as_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/display_filter_expression_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/dissector_tables_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/enabled_protocols_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/endpoint_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/expert_info_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/export_dissection_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/extcap_argument_file.h
	${CMAKE_SOURCE_DIR}/ui/qt/extcap_argument_multiselect.h
	${CMAKE_SOURCE_DIR}/ui/qt/extcap_argument.h
	${CMAKE_SOURCE_DIR}/ui/qt/extcap_options_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/file_set_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/filter_action.h
	${CMAKE_SOURCE_DIR}/ui/qt/filter_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/filter_expression_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/follow_stream_action.h
	${CMAKE_SOURCE_DIR}/ui/qt/follow_stream_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/font_color_preferences_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/funnel_statistics.h
	${CMAKE_SOURCE_DIR}/ui/qt/funnel_string_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/funnel_text_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/geometry_state_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/glib_mainloop_on_qeventloop.h
	${CMAKE_SOURCE_DIR}/ui/qt/import_text_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/interface_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/interface_toolbar_reader.h
	${CMAKE_SOURCE_DIR}/ui/qt/interface_toolbar.h
	${CMAKE_SOURCE_DIR}/ui/qt/io_console_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/io_graph_action.h
	${CMAKE_SOURCE_DIR}/ui/qt/io_graph_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/layout_preferences_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/main_application.h
	${CMAKE_SOURCE_DIR}/ui/qt/main_status_bar.h
	${CMAKE_SOURCE_DIR}/ui/qt/main_window_preferences_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/main_window.h
	${CMAKE_SOURCE_DIR}/ui/qt/manage_interfaces_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/module_preferences_scroll_area.h
	${CMAKE_SOURCE_DIR}/ui/qt/packet_comment_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/packet_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/packet_format_group_box.h
	${CMAKE_SOURCE_DIR}/ui/qt/packet_list.h
	${CMAKE_SOURCE_DIR}/ui/qt/packet_range_group_box.h
	${CMAKE_SOURCE_DIR}/ui/qt/preference_editor_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/preferences_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/print_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/profile_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/progress_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/proto_tree.h
	${CMAKE_SOURCE_DIR}/ui/qt/protocol_hierarchy_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/protocol_preferences_menu.h
	${CMAKE_SOURCE_DIR}/ui/qt/recent_file_status.h
	${CMAKE_SOURCE_DIR}/ui/qt/resolved_addresses_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/response_time_delay_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/rsa_keys_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/search_frame.h
	# XXX Depends on RTP Stream Dialog
	# ${CMAKE_SOURCE_DIR}/ui/qt/sequence_diagram.h
	# ${CMAKE_SOURCE_DIR}/ui/qt/sequence_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/show_packet_bytes_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/simple_statistics_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/stats_tree_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/supported_protocols_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/tabnav_tree_widget.h
	${CMAKE_SOURCE_DIR}/ui/qt/tap_parameter_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/tcp_stream_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/time_shift_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/traffic_table_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/uat_dialog.h
	${CMAKE_SOURCE_DIR}/ui/qt/uat_frame.h
	${CMAKE_SOURCE_DIR}/ui/qt/welcome_page.h
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_dialog.h
)

if(WIRESHARK_CUSTOM_QT_HEADERS)
	list(APPEND WIRESHARK_QT_HEADERS
		${CMAKE_SOURCE_DIR}/ui/qt/${WIRESHARK_CUSTOM_QT_HEADERS}
	)
endif()

if(ENABLE_PCAP)
	list(APPEND WIRESHARK_QT_HEADERS
		${CMAKE_SOURCE_DIR}/ui/qt/capture_info_dialog.h
	)
	if(HAVE_PCAP_REMOTE)
		list(APPEND WIRESHARK_QT_HEADERS
			${CMAKE_SOURCE_DIR}/ui/qt/remote_capture_dialog.h
			${CMAKE_SOURCE_DIR}/ui/qt/remote_settings_dialog.h
		)
	endif()
endif()

set (LOGRAY_QT_HEADERS
	logray_application.h
	logray_main_window.h
	${WIRESHARK_QT_HEADERS}
)

set(WIRESHARK_WIDGET_SRCS
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/additional_toolbar.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/apply_line_edit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/byte_view_text.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/capture_filter_combo.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/capture_filter_edit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/clickable_label.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/copy_from_profile_button.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/detachable_tabwidget.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/display_filter_combo.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/display_filter_edit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/dissector_syntax_line_edit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/dissector_tables_view.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/drag_drop_toolbar.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/drag_label.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/editor_file_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/elided_label.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/expert_info_view.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/field_filter_edit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/filter_expression_toolbar.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/find_line_edit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/follow_stream_text.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/interface_toolbar_lineedit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/label_stack.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/overlay_scroll_bar.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/packet_list_header.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/path_selection_edit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/pref_module_view.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/profile_tree_view.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/qcp_axis_ticker_elided.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/qcp_axis_ticker_si.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/qcp_string_legend_item.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/range_syntax_lineedit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/resize_header_view.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/resolved_addresses_view.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/rowmove_tree_view.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/splash_overlay.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/stock_icon_tool_button.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/syntax_line_edit.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/wireless_timeline.cpp # Required by PacketListModel
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/tabnav_tree_view.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/traffic_tab.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/traffic_tree.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/traffic_types_list.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/wireshark_file_dialog.cpp
)

set (LOGRAY_WIDGET_SRCS ${WIRESHARK_WIDGET_SRCS})

set(WIRESHARK_3RD_PARTY_WIDGET_SRCS
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/qcustomplot.cpp
)

set (LOGRAY_3RD_PARTY_WIDGET_SRCS ${WIRESHARK_3RD_PARTY_WIDGET_SRCS})

set(WIRESHARK_MANAGER_SRCS
	${CMAKE_SOURCE_DIR}/ui/qt/manager/preference_manager.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/manager/wireshark_preference.cpp
)

set (LOGRAY_MANAGER_SRCS ${WIRESHARK_MANAGER_SRCS})

set(WIRESHARK_UTILS_SRCS
	${CMAKE_SOURCE_DIR}/ui/qt/utils/color_utils.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/utils/data_printer.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/utils/field_information.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/utils/frame_information.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/utils/profile_switcher.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/utils/proto_node.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/utils/qt_ui_utils.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/utils/stock_icon.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/utils/wireshark_mime_data.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/utils/wireshark_zip_helper.cpp
)

set (LOGRAY_UTILS_SRCS ${WIRESHARK_UTILS_SRCS})

set(WIRESHARK_MODEL_SRCS
	${CMAKE_SOURCE_DIR}/ui/qt/models/astringlist_list_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/atap_data_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/cache_proxy_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/coloring_rules_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/coloring_rules_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/column_list_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/decode_as_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/decode_as_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/dissector_tables_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/enabled_protocols_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/expert_info_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/expert_info_proxy_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/fileset_entry_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/filter_list_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/info_proxy_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/interface_sort_filter_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/interface_tree_cache_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/interface_tree_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/numeric_value_chooser_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/packet_list_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/packet_list_record.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/path_selection_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/percent_bar_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/pref_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/pref_models.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/profile_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/proto_tree_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/related_packet_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/resolved_addresses_models.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/sparkline_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/supported_protocols_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/timeline_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/uat_delegate.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/uat_model.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/models/url_link_delegate.cpp
)

set (LOGRAY_MODEL_SRCS ${WIRESHARK_MODEL_SRCS})

set(WIRESHARK_QT_SRC
	${CMAKE_SOURCE_DIR}/ui/qt/about_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/accordion_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/address_editor_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/byte_view_tab.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/capture_comment_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/capture_file_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/capture_file_properties_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/capture_file.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/capture_filter_syntax_worker.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/capture_options_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/capture_preferences_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/coloring_rules_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/column_editor_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/column_preferences_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/compiled_filter_output.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/conversation_colorize_action.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/conversation_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/conversation_hash_tables_dialog.cpp
	# XXX Required by packet list
	${CMAKE_SOURCE_DIR}/ui/qt/decode_as_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/display_filter_expression_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/dissector_tables_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/enabled_protocols_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/endpoint_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/export_dissection_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/extcap_argument_file.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/extcap_argument_multiselect.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/extcap_argument.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/extcap_options_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/file_set_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/filter_action.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/filter_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/filter_expression_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/follow_stream_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/follow_stream_action.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/font_color_preferences_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/funnel_string_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/funnel_text_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/geometry_state_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/glib_mainloop_on_qeventloop.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/import_text_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/interface_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/interface_toolbar_reader.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/interface_toolbar.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/io_console_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/io_graph_action.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/layout_preferences_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/main_application.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/main_status_bar.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/main_window_layout.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/main_window_preferences_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/main_window.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/manage_interfaces_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/module_preferences_scroll_area.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/packet_comment_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/packet_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/packet_format_group_box.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/packet_list.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/packet_range_group_box.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/preference_editor_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/preferences_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/print_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/profile_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/progress_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/proto_tree.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/protocol_hierarchy_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/protocol_preferences_menu.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/recent_file_status.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/resolved_addresses_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/response_time_delay_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/rsa_keys_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/search_frame.cpp
	# XXX Depends on RTP Stream Dialog
	# ${CMAKE_SOURCE_DIR}/ui/qt/sequence_diagram.cpp
	# ${CMAKE_SOURCE_DIR}/ui/qt/sequence_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/show_packet_bytes_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/simple_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/simple_statistics_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/supported_protocols_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/tabnav_tree_widget.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/tap_parameter_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/tcp_stream_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/time_shift_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/traffic_table_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/uat_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/uat_frame.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/welcome_page.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_dialog.cpp
)

if(WIRESHARK_CUSTOM_QT_SRCS)
	list(APPEND WIRESHARK_QT_SRC
		${CMAKE_SOURCE_DIR}/ui/qt/${WIRESHARK_CUSTOM_QT_SRCS}
	)
endif()

if(ENABLE_PCAP)
	list(APPEND WIRESHARK_QT_SRC
		${CMAKE_SOURCE_DIR}/ui/qt/capture_info_dialog.cpp
	)
	if(HAVE_PCAP_REMOTE)
		list(APPEND WIRESHARK_QT_SRC
			${CMAKE_SOURCE_DIR}/ui/qt/remote_capture_dialog.cpp
			${CMAKE_SOURCE_DIR}/ui/qt/remote_settings_dialog.cpp
		)
	endif()
endif()

set (LOGRAY_QT_SRC
	logray_application.cpp
	logray_main.cpp
	logray_main_window.cpp
	logray_main_window_slots.cpp
	${WIRESHARK_QT_SRC})

set(WIRESHARK_QT_TAP_SRC
	${CMAKE_SOURCE_DIR}/ui/qt/expert_info_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/funnel_statistics.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/io_graph_dialog.cpp
	${CMAKE_SOURCE_DIR}/ui/qt/stats_tree_dialog.cpp
	${WIRESHARK_CUSTOM_TAP_SRC}
)

set (LOGRAY_QT_TAP_SRC ${WIRESHARK_QT_TAP_SRC})

set(WIRESHARK_QT_FILES
	${WIRESHARK_QT_SRC}
	${WIRESHARK_QT_TAP_SRC}
)

set (LOGRAY_QT_FILES ${WIRESHARK_QT_FILES})

set(WIRESHARK_QT_UI
	${CMAKE_SOURCE_DIR}/ui/qt/about_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/address_editor_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/capture_comment_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/capture_file_properties_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/capture_info_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/capture_options_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/capture_preferences_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/coloring_rules_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/column_editor_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/column_preferences_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/compiled_filter_output.ui
	${CMAKE_SOURCE_DIR}/ui/qt/conversation_hash_tables_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/decode_as_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/display_filter_expression_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/dissector_tables_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/enabled_protocols_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/expert_info_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/extcap_options_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/file_set_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/filter_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/filter_expression_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/follow_stream_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/font_color_preferences_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/funnel_string_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/funnel_text_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/import_text_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/interface_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/interface_toolbar.ui
	${CMAKE_SOURCE_DIR}/ui/qt/io_console_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/io_graph_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/layout_preferences_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/main_window_preferences_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/manage_interfaces_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/module_preferences_scroll_area.ui
	${CMAKE_SOURCE_DIR}/ui/qt/packet_comment_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/packet_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/packet_format_group_box.ui
	${CMAKE_SOURCE_DIR}/ui/qt/packet_range_group_box.ui
	${CMAKE_SOURCE_DIR}/ui/qt/preference_editor_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/preferences_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/print_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/profile_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/progress_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/protocol_hierarchy_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/resolved_addresses_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/rsa_keys_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/search_frame.ui
	# XXX Depends on RTP Stream Dialog
	# ${CMAKE_SOURCE_DIR}/ui/qt/sequence_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/show_packet_bytes_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/supported_protocols_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/tap_parameter_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/tcp_stream_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/time_shift_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/traffic_table_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/uat_dialog.ui
	${CMAKE_SOURCE_DIR}/ui/qt/uat_frame.ui
	${CMAKE_SOURCE_DIR}/ui/qt/welcome_page.ui
	${CMAKE_SOURCE_DIR}/ui/qt/widgets/splash_overlay.ui
)

if(HAVE_PCAP_REMOTE)
	list(APPEND WIRESHARK_QT_UI
		${CMAKE_SOURCE_DIR}/ui/qt/remote_capture_dialog.ui
		${CMAKE_SOURCE_DIR}/ui/qt/remote_settings_dialog.ui
	)
endif()

set (LOGRAY_QT_UI
	logray_main_window.ui
	${WIRESHARK_QT_UI}
)

set(WIRESHARK_QT_TS
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_de.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_en.ts # lupdate -pluralonly
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_es.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_fr.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_it.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_ja_JP.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_pl.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_ru.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_sv.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_tr_TR.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_uk.ts
	${CMAKE_SOURCE_DIR}/ui/qt/wireshark_zh_CN.ts
)

set(LOGRAY_QT_TS
	logray_en.ts
	${WIRESHARK_QT_TS}
)

foreach(_file ${LOGRAY_QT_TS})
	get_filename_component(_qresource ${_file} NAME_WE)
	set(_qresource_qm "${_qresource}.qm")
	set(i18n_qresource "${i18n_qresource}\n    <file>${_qresource_qm}</file>")
endforeach()
configure_file(i18n.qrc.in ${CMAKE_CURRENT_BINARY_DIR}/i18n.qrc)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/authors.qrc"
"<RCC>\n"
"    <qresource prefix=\"/about\">\n"
"        <file compress-algo=\"zstd\">authors.csv</file>\n"
"    </qresource>\n"
"</RCC>\n"
)

add_custom_command(
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/authors.csv
	COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/make-authors-csv.py
			< ${CMAKE_SOURCE_DIR}/AUTHORS
			> ${CMAKE_CURRENT_BINARY_DIR}/authors.csv
	DEPENDS
		${CMAKE_SOURCE_DIR}/tools/make-authors-csv.py
		${CMAKE_SOURCE_DIR}/AUTHORS
)

set(LOGRAY_QT_QRC
	${CMAKE_SOURCE_DIR}/resources/about.qrc
	${CMAKE_SOURCE_DIR}/resources/languages/languages.qrc
	${CMAKE_SOURCE_DIR}/resources/layout.qrc
	${CMAKE_SOURCE_DIR}/resources/lricon.qrc
	${CMAKE_SOURCE_DIR}/resources/stock_icons.qrc
	${CMAKE_CURRENT_BINARY_DIR}/i18n.qrc
	${CMAKE_CURRENT_BINARY_DIR}/authors.qrc
	${CMAKE_CURRENT_BINARY_DIR}/authors.csv
)

if(NOT Qt${qtver}Widgets_VERSION VERSION_LESS "5.9")
	# Drop the file modification time of source files from generated files
	# to help with reproducible builds. We do not use QFileInfo.lastModified
	# so this has no unwanted side effects. This mtime started appearing in
	# Qt 5.8. The option to force the old file format without mtime was
	# added in Qt 5.9. See https://bugreports.qt.io/browse/QTBUG-58769.
	# Force the compression algorithm to zlib, since zstd requires format
	# version 3. See https://gitlab.com/wireshark/wireshark/-/issues/18100.
	# Use the number of dashes for each argument as documented at
	# https://doc.qt.io/qt-6/rcc.html.
	set(CMAKE_AUTORCC_OPTIONS --format-version 1)
	if(Qt${qtver}Widgets_VERSION VERSION_GREATER_EQUAL "5.13")
		list(APPEND CMAKE_AUTORCC_OPTIONS -compress-algo zlib)
	endif()
endif()

if (USE_qt6)
	QT6_ADD_TRANSLATION(LOGRAY_QT_QM ${LOGRAY_QT_TS} OPTIONS -silent)
elseif(NOT Qt${qtver}Widgets_VERSION VERSION_LESS "5.11")
	QT5_ADD_TRANSLATION(LOGRAY_QT_QM ${LOGRAY_QT_TS} OPTIONS -silent)
else()
	QT5_ADD_TRANSLATION(LOGRAY_QT_QM ${LOGRAY_QT_TS})
endif()

add_custom_target(
	logray_translations
	DEPENDS
		${LOGRAY_QT_QM}
)
set_target_properties(logray_translations PROPERTIES FOLDER "UI")

set_source_files_properties(
	${LOGRAY_QT_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

set_source_files_properties(
	logray-tap-register.c
	PROPERTIES
	SKIP_AUTOGEN ON
)

add_definitions(${QT_DEFINITIONS})

register_tap_files(logray-tap-register.c
	${LOGRAY_QT_TAP_SRC}
)

source_group("ui\\UIC Files" FILES ${LOGRAY_QT_UI})
source_group("ui\\qrc" FILES ${LOGRAY_QT_QRC})
source_group("ui\\Header" FILES ${LOGRAY_QT_HEADERS})
source_group("ui\\Widget Header" FILES ${LOGRAY_WIDGET_HEADERS})
source_group("ui\\Widget Source" FILES ${LOGRAY_WIDGET_SRCS})
source_group("ui\\Utils Headers Files" FILES ${LOGRAY_UTILS_HEADERS})
source_group("ui\\Utils Source" FILES ${LOGRAY_UTILS_SRCS})
source_group("ui\\Models Headers" FILES ${LOGRAY_MODEL_HEADERS})
source_group("ui\\Models Source" FILES ${LOGRAY_MODEL_SRCS})
source_group("ui\\Manager Headers" FILES ${LOGRAY_MANAGER_HEADERS})
source_group("ui\\Manager Source" FILES ${LOGRAY_MANAGER_SRCS})

add_library(ui_logray OBJECT
	#Included so that Visual Studio can properly put header files in solution
	${LOGRAY_QT_HEADERS}
	${LOGRAY_WIDGET_HEADERS}
	${LOGRAY_3RD_PARTY_WIDGET_HEADERS}
	${LOGRAY_MANAGER_HEADERS}
	${LOGRAY_UTILS_HEADERS}
	${LOGRAY_MODEL_HEADERS}

	${LOGRAY_QT_SRC}
	${LOGRAY_WIDGET_SRCS}
	${LOGRAY_3RD_PARTY_WIDGET_SRCS}
	${LOGRAY_MANAGER_SRCS}
	${LOGRAY_UTILS_SRCS}
	${LOGRAY_MODEL_SRCS}

	# For AUTOUIC and AUTORCC.
	${LOGRAY_QT_UI}
	${LOGRAY_QT_QRC}

	${LOGRAY_QT_TAP_SRC}
	logray-tap-register.c
)

target_include_directories(ui_logray
	SYSTEM PRIVATE
		# Include Qt before anything else, see the comment about
		# QT5_INCLUDE_DIRS in the top-level CMakeLists.txt
		# Basically, qt@5 headers should be prioritized over qt@6 which
		# would be found due to GCRYPT_INCLUDE_DIRS=/usr/local/include
		${QT5_INCLUDE_DIRS}
		${GCRYPT_INCLUDE_DIRS}
		${MINIZIP_INCLUDE_DIRS}
		${MINIZIPNG_INCLUDE_DIRS}
		${PCAP_INCLUDE_DIRS}
		${SPEEXDSP_INCLUDE_DIRS}
		${WINSPARKLE_INCLUDE_DIRS}
	PRIVATE
		${CMAKE_CURRENT_BINARY_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_SOURCE_DIR}/ui/qt
)

if(USE_qt6)
	target_link_libraries(ui_logray PUBLIC
		Qt6::Widgets
		Qt6::Core5Compat
		Qt6::Concurrent
		Qt6::PrintSupport
	)
	if(Qt6Multimedia_FOUND)
		target_link_libraries(ui_logray PUBLIC Qt6::Multimedia)
	endif()
	if(Qt6DBus_FOUND)
		target_link_libraries(ui_logray PUBLIC Qt6::DBus)
	endif()
endif()

target_compile_definitions(ui_logray
	PUBLIC
		${QT5_COMPILE_DEFINITIONS}
)

set_target_properties(ui_logray PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "UI"
	AUTOMOC ON
	AUTOUIC ON
	AUTORCC ON
	# Ensure .qm files are generated before autogenerating i18n.qrc
	AUTOGEN_TARGET_DEPENDS "${LOGRAY_QT_QM}"
)

if(MSVC)
	set_target_properties(ui_logray PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
endif()

CHECKAPI(
	NAME
		ui-qt-logray
	SWITCHES
		--nocheck-shadow
	SOURCES
		# QCustomPlot (LOGRAY_3RD_PARTY_WIDGET_{HEADERS,SRCS}) uses
		# prohibited APIs.
		${LOGRAY_QT_HEADERS}
		${LOGRAY_WIDGET_HEADERS}
		${LOGRAY_MANAGER_HEADERS}
		${LOGRAY_UTILS_HEADERS}
		${LOGRAY_MODEL_HEADERS}

		${LOGRAY_QT_SRC}
		${LOGRAY_WIDGET_SRCS}
		${LOGRAY_MANAGER_SRCS}
		${LOGRAY_UTILS_SRCS}
		${LOGRAY_MODEL_SRCS}
		${LOGRAY_QT_TAP_SRC}
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
