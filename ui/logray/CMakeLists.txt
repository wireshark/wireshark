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
	../qt/widgets/additional_toolbar.h
	../qt/widgets/apply_line_edit.h
	../qt/widgets/byte_view_text.h
	../qt/widgets/capture_filter_combo.h
	../qt/widgets/capture_filter_edit.h
	../qt/widgets/clickable_label.h
	../qt/widgets/copy_from_profile_button.h
	../qt/widgets/detachable_tabwidget.h
	../qt/widgets/display_filter_combo.h
	../qt/widgets/display_filter_edit.h
	../qt/widgets/dissector_tables_view.h
	../qt/widgets/drag_drop_toolbar.h
	../qt/widgets/drag_label.h
	../qt/widgets/editor_file_dialog.h
	../qt/widgets/elided_label.h
	../qt/widgets/expert_info_view.h
	../qt/widgets/export_objects_view.h
	../qt/widgets/field_filter_edit.h
	../qt/widgets/filter_expression_toolbar.h
	../qt/widgets/find_line_edit.h
	../qt/widgets/follow_stream_text.h
	../qt/widgets/interface_toolbar_lineedit.h
	../qt/widgets/label_stack.h
	../qt/widgets/overlay_scroll_bar.h
	../qt/widgets/packet_list_header.h
	../qt/widgets/path_selection_edit.h
	../qt/widgets/pref_module_view.h
	../qt/widgets/profile_tree_view.h
	../qt/widgets/range_syntax_lineedit.h
	../qt/widgets/splash_overlay.h
	../qt/widgets/stock_icon_tool_button.h
	../qt/widgets/syntax_line_edit.h
	../qt/widgets/wireless_timeline.h # Required by PacketListModel
	../qt/widgets/tabnav_tree_view.h
	../qt/widgets/traffic_tab.h
	../qt/widgets/traffic_tree.h
	../qt/widgets/traffic_types_list.h
	../qt/widgets/wireshark_file_dialog.h
)

set (LOGRAY_WIDGET_HEADERS ${WIRESHARK_WIDGET_HEADERS})

set(WIRESHARK_3RD_PARTY_WIDGET_HEADERS
	../qt/widgets/qcustomplot.h
)

set (LOGRAY_3RD_PARTY_WIDGET_HEADERS ${WIRESHARK_3RD_PARTY_WIDGET_HEADERS})

set(WIRESHARK_MANAGER_HEADERS
	../qt/manager/preference_manager.h
	../qt/manager/wireshark_preference.h
)

set (LOGRAY_MANAGER_HEADERS ${WIRESHARK_MANAGER_HEADERS})

set(WIRESHARK_UTILS_HEADERS
	../qt/utils/color_utils.h
	../qt/utils/data_printer.h
	../qt/utils/field_information.h
	../qt/utils/frame_information.h
	../qt/utils/idata_printable.h
	../qt/utils/proto_node.h
	../qt/utils/qt_ui_utils.h
	../qt/utils/stock_icon.h
	../qt/utils/tango_colors.h
	../qt/utils/variant_pointer.h
	../qt/utils/wireshark_mime_data.h
	../qt/utils/wireshark_zip_helper.h
)

set (LOGRAY_UTILS_HEADERS ${WIRESHARK_UTILS_HEADERS})

set(WIRESHARK_MODEL_HEADERS
	../qt/models/astringlist_list_model.h
	../qt/models/atap_data_model.h
	../qt/models/cache_proxy_model.h
	../qt/models/coloring_rules_delegate.h
	../qt/models/coloring_rules_model.h
	../qt/models/column_list_model.h
	../qt/models/decode_as_delegate.h
	../qt/models/decode_as_model.h
	../qt/models/dissector_tables_model.h
	../qt/models/enabled_protocols_model.h
	../qt/models/expert_info_model.h
	../qt/models/expert_info_proxy_model.h
	../qt/models/export_objects_model.h
	../qt/models/fileset_entry_model.h
	../qt/models/filter_list_model.h
	../qt/models/info_proxy_model.h
	../qt/models/interface_sort_filter_model.h
	../qt/models/interface_tree_cache_model.h
	../qt/models/interface_tree_model.h
	../qt/models/numeric_value_chooser_delegate.h
	../qt/models/packet_list_model.h
	../qt/models/packet_list_record.h
	../qt/models/path_selection_delegate.h
	../qt/models/percent_bar_delegate.h
	../qt/models/pref_delegate.h
	../qt/models/pref_models.h
	../qt/models/profile_model.h
	../qt/models/proto_tree_model.h
	../qt/models/related_packet_delegate.h
	../qt/models/resolved_addresses_models.h
	../qt/models/sparkline_delegate.h
	../qt/models/supported_protocols_model.h
	../qt/models/timeline_delegate.h
	../qt/models/tree_model_helpers.h
	../qt/models/uat_delegate.h
	../qt/models/uat_model.h
	../qt/models/url_link_delegate.h
)

set (LOGRAY_MODEL_HEADERS ${WIRESHARK_MODEL_HEADERS})

# All .h files which inherit from QObject aka which use the Q_OBJECT macro
# need to go here.
set(WIRESHARK_QT_HEADERS
	../qt/about_dialog.h
	../qt/accordion_frame.h
	../qt/address_editor_frame.h
	../qt/byte_view_tab.h
	../qt/capture_file_dialog.h
	../qt/capture_file_properties_dialog.h
	../qt/capture_file.h
	../qt/capture_filter_syntax_worker.h
	../qt/capture_options_dialog.h
	../qt/capture_preferences_frame.h
	../qt/coloring_rules_dialog.h
	../qt/column_editor_frame.h
	../qt/column_preferences_frame.h
	../qt/compiled_filter_output.h
	../qt/conversation_colorize_action.h
	../qt/conversation_dialog.h
	../qt/conversation_hash_tables_dialog.h
	../qt/decode_as_dialog.h
	../qt/display_filter_expression_dialog.h
	../qt/dissector_tables_dialog.h
	../qt/enabled_protocols_dialog.h
	../qt/endpoint_dialog.h
	../qt/expert_info_dialog.h
	../qt/export_dissection_dialog.h
	../qt/export_object_action.h
	../qt/export_object_dialog.h
	../qt/export_pdu_dialog.h
	../qt/extcap_argument_file.h
	../qt/extcap_argument_multiselect.h
	../qt/extcap_argument.h
	../qt/extcap_options_dialog.h
	../qt/file_set_dialog.h
	../qt/filter_action.h
	../qt/filter_dialog.h
	../qt/filter_dialog.h
	../qt/filter_expression_frame.h
	../qt/follow_stream_dialog.h
	../qt/font_color_preferences_frame.h
	../qt/funnel_statistics.h
	../qt/funnel_string_dialog.h
	../qt/funnel_text_dialog.h
	../qt/geometry_state_dialog.h
	../qt/glib_mainloop_on_qeventloop.h
	../qt/import_text_dialog.h
	../qt/interface_frame.h
	../qt/interface_toolbar_reader.h
	../qt/interface_toolbar.h
	../qt/io_graph_dialog.h
	../qt/layout_preferences_frame.h
	../qt/main_application.h
	../qt/main_status_bar.h
	../qt/main_window_preferences_frame.h
	../qt/main_window.h
	../qt/manage_interfaces_dialog.h
	../qt/module_preferences_scroll_area.h
	../qt/packet_comment_dialog.h
	../qt/packet_diagram.h
	../qt/packet_dialog.h
	../qt/packet_format_group_box.h
	../qt/packet_list.h
	../qt/packet_range_group_box.h
	../qt/preference_editor_frame.h
	../qt/preferences_dialog.h
	../qt/print_dialog.h
	../qt/profile_dialog.h
	../qt/progress_frame.h
	../qt/proto_tree.h
	../qt/protocol_hierarchy_dialog.h
	../qt/protocol_preferences_menu.h
	../qt/recent_file_status.h
	../qt/resolved_addresses_dialog.h
	../qt/response_time_delay_dialog.h
	../qt/rsa_keys_frame.h
	../qt/search_frame.h
	# XXX Depends on RTP Stream Dialog
	# ../qt/sequence_diagram.h
	# ../qt/sequence_dialog.h
	../qt/show_packet_bytes_dialog.h
	../qt/simple_statistics_dialog.h
	../qt/stats_tree_dialog.h
	../qt/supported_protocols_dialog.h
	../qt/tabnav_tree_widget.h
	../qt/tap_parameter_dialog.h
	../qt/tcp_stream_dialog.h
	../qt/time_shift_dialog.h
	../qt/traffic_table_dialog.h
	../qt/uat_dialog.h
	../qt/uat_frame.h
	../qt/welcome_page.h
	../qt/wireshark_dialog.h
	../qt/${WIRESHARK_CUSTOM_QT_HEADERS}
)

if(ENABLE_PCAP)
	list(APPEND WIRESHARK_QT_HEADERS
		../qt/capture_info_dialog.h
	)
	if(HAVE_PCAP_REMOTE)
		list(APPEND WIRESHARK_QT_HEADERS
			../qt/remote_capture_dialog.h
			../qt/remote_settings_dialog.h
		)
	endif()
endif()

set (LOGRAY_QT_HEADERS
	logray_application.h
	logray_main_window.h
	${WIRESHARK_QT_HEADERS}
)

set(WIRESHARK_WIDGET_SRCS
	../qt/widgets/additional_toolbar.cpp
	../qt/widgets/apply_line_edit.cpp
	../qt/widgets/byte_view_text.cpp
	../qt/widgets/capture_filter_combo.cpp
	../qt/widgets/capture_filter_edit.cpp
	../qt/widgets/clickable_label.cpp
	../qt/widgets/copy_from_profile_button.cpp
	../qt/widgets/detachable_tabwidget.cpp
	../qt/widgets/display_filter_combo.cpp
	../qt/widgets/display_filter_edit.cpp
	../qt/widgets/dissector_tables_view.cpp
	../qt/widgets/drag_drop_toolbar.cpp
	../qt/widgets/drag_label.cpp
	../qt/widgets/editor_file_dialog.cpp
	../qt/widgets/elided_label.cpp
	../qt/widgets/expert_info_view.cpp
	../qt/widgets/export_objects_view.cpp
	../qt/widgets/field_filter_edit.cpp
	../qt/widgets/filter_expression_toolbar.cpp
	../qt/widgets/find_line_edit.cpp
	../qt/widgets/follow_stream_text.cpp
	../qt/widgets/interface_toolbar_lineedit.cpp
	../qt/widgets/label_stack.cpp
	../qt/widgets/overlay_scroll_bar.cpp
	../qt/widgets/packet_list_header.cpp
	../qt/widgets/path_selection_edit.cpp
	../qt/widgets/pref_module_view.cpp
	../qt/widgets/profile_tree_view.cpp
	../qt/widgets/range_syntax_lineedit.cpp
	../qt/widgets/splash_overlay.cpp
	../qt/widgets/stock_icon_tool_button.cpp
	../qt/widgets/syntax_line_edit.cpp
	../qt/widgets/wireless_timeline.cpp # Required by PacketListModel
	../qt/widgets/tabnav_tree_view.cpp
	../qt/widgets/traffic_tab.cpp
	../qt/widgets/traffic_tree.cpp
	../qt/widgets/traffic_types_list.cpp
	../qt/widgets/wireshark_file_dialog.cpp
)

set (LOGRAY_WIDGET_SRCS ${WIRESHARK_WIDGET_SRCS})

set(WIRESHARK_3RD_PARTY_WIDGET_SRCS
	../qt/widgets/qcustomplot.cpp
)

set (LOGRAY_3RD_PARTY_WIDGET_SRCS ${WIRESHARK_3RD_PARTY_WIDGET_SRCS})

set(WIRESHARK_MANAGER_SRCS
	../qt/manager/preference_manager.cpp
	../qt/manager/wireshark_preference.cpp
)

set (LOGRAY_MANAGER_SRCS ${WIRESHARK_MANAGER_SRCS})

set(WIRESHARK_UTILS_SRCS
	../qt/utils/color_utils.cpp
	../qt/utils/data_printer.cpp
	../qt/utils/field_information.cpp
	../qt/utils/frame_information.cpp
	../qt/utils/proto_node.cpp
	../qt/utils/qt_ui_utils.cpp
	../qt/utils/stock_icon.cpp
	../qt/utils/wireshark_mime_data.cpp
	../qt/utils/wireshark_zip_helper.cpp
)

set (LOGRAY_UTILS_SRCS ${WIRESHARK_UTILS_SRCS})

set(WIRESHARK_MODEL_SRCS
	../qt/models/astringlist_list_model.cpp
	../qt/models/atap_data_model.cpp
	../qt/models/cache_proxy_model.cpp
	../qt/models/coloring_rules_delegate.cpp
	../qt/models/coloring_rules_model.cpp
	../qt/models/column_list_model.cpp
	../qt/models/decode_as_delegate.cpp
	../qt/models/decode_as_model.cpp
	../qt/models/dissector_tables_model.cpp
	../qt/models/enabled_protocols_model.cpp
	../qt/models/expert_info_model.cpp
	../qt/models/expert_info_proxy_model.cpp
	../qt/models/export_objects_model.cpp
	../qt/models/fileset_entry_model.cpp
	../qt/models/filter_list_model.cpp
	../qt/models/info_proxy_model.cpp
	../qt/models/interface_sort_filter_model.cpp
	../qt/models/interface_tree_cache_model.cpp
	../qt/models/interface_tree_model.cpp
	../qt/models/numeric_value_chooser_delegate.cpp
	../qt/models/packet_list_model.cpp
	../qt/models/packet_list_record.cpp
	../qt/models/path_selection_delegate.cpp
	../qt/models/percent_bar_delegate.cpp
	../qt/models/pref_delegate.cpp
	../qt/models/pref_models.cpp
	../qt/models/profile_model.cpp
	../qt/models/proto_tree_model.cpp
	../qt/models/related_packet_delegate.cpp
	../qt/models/resolved_addresses_models.cpp
	../qt/models/sparkline_delegate.cpp
	../qt/models/supported_protocols_model.cpp
	../qt/models/timeline_delegate.cpp
	../qt/models/uat_delegate.cpp
	../qt/models/uat_model.cpp
	../qt/models/url_link_delegate.cpp
)

set (LOGRAY_MODEL_SRCS ${WIRESHARK_MODEL_SRCS})

set(WIRESHARK_QT_SRC
	../qt/about_dialog.cpp
	../qt/accordion_frame.cpp
	../qt/address_editor_frame.cpp
	../qt/byte_view_tab.cpp
	../qt/capture_file_dialog.cpp
	../qt/capture_file_properties_dialog.cpp
	../qt/capture_file.cpp
	../qt/capture_filter_syntax_worker.cpp
	../qt/capture_options_dialog.cpp
	../qt/capture_preferences_frame.cpp
	../qt/coloring_rules_dialog.cpp
	../qt/column_editor_frame.cpp
	../qt/column_preferences_frame.cpp
	../qt/compiled_filter_output.cpp
	../qt/conversation_colorize_action.cpp
	../qt/conversation_dialog.cpp
	../qt/conversation_hash_tables_dialog.cpp
	../qt/decode_as_dialog.cpp
	../qt/display_filter_expression_dialog.cpp
	../qt/dissector_tables_dialog.cpp
	../qt/enabled_protocols_dialog.cpp
	../qt/endpoint_dialog.cpp
	../qt/export_dissection_dialog.cpp
	../qt/export_object_action.cpp
	../qt/export_object_dialog.cpp
	../qt/export_pdu_dialog.cpp
	../qt/extcap_argument_file.cpp
	../qt/extcap_argument_multiselect.cpp
	../qt/extcap_argument.cpp
	../qt/extcap_options_dialog.cpp
	../qt/file_set_dialog.cpp
	../qt/filter_action.cpp
	../qt/filter_dialog.cpp
	../qt/filter_expression_frame.cpp
	../qt/follow_stream_dialog.cpp
	../qt/font_color_preferences_frame.cpp
	../qt/funnel_string_dialog.cpp
	../qt/funnel_text_dialog.cpp
	../qt/geometry_state_dialog.cpp
	../qt/glib_mainloop_on_qeventloop.cpp
	../qt/import_text_dialog.cpp
	../qt/interface_frame.cpp
	../qt/interface_toolbar_reader.cpp
	../qt/interface_toolbar.cpp
	../qt/layout_preferences_frame.cpp
	../qt/main_application.cpp
	../qt/main_status_bar.cpp
	../qt/main_window_layout.cpp
	../qt/main_window_preferences_frame.cpp
	../qt/main_window.cpp
	../qt/manage_interfaces_dialog.cpp
	../qt/module_preferences_scroll_area.cpp
	../qt/packet_comment_dialog.cpp
	../qt/packet_diagram.cpp
	../qt/packet_dialog.cpp
	../qt/packet_format_group_box.cpp
	../qt/packet_list.cpp
	../qt/packet_range_group_box.cpp
	../qt/preference_editor_frame.cpp
	../qt/preferences_dialog.cpp
	../qt/print_dialog.cpp
	../qt/profile_dialog.cpp
	../qt/progress_frame.cpp
	../qt/proto_tree.cpp
	../qt/protocol_hierarchy_dialog.cpp
	../qt/protocol_preferences_menu.cpp
	../qt/recent_file_status.cpp
	../qt/resolved_addresses_dialog.cpp
	../qt/response_time_delay_dialog.cpp
	../qt/rsa_keys_frame.cpp
	../qt/search_frame.cpp
	# XXX Depends on RTP Stream Dialog
	# ../qt/sequence_diagram.cpp
	# ../qt/sequence_dialog.cpp
	../qt/show_packet_bytes_dialog.cpp
	../qt/simple_dialog.cpp
	../qt/simple_statistics_dialog.cpp
	../qt/supported_protocols_dialog.cpp
	../qt/tabnav_tree_widget.cpp
	../qt/tap_parameter_dialog.cpp
	../qt/tcp_stream_dialog.cpp
	../qt/time_shift_dialog.cpp
	../qt/traffic_table_dialog.cpp
	../qt/uat_dialog.cpp
	../qt/uat_frame.cpp
	../qt/welcome_page.cpp
	../qt/wireshark_dialog.cpp
	../qt/${WIRESHARK_CUSTOM_QT_SRCS}
)

if(ENABLE_PCAP)
	list(APPEND WIRESHARK_QT_SRC
		../qt/capture_info_dialog.cpp
	)
	if(HAVE_PCAP_REMOTE)
		list(APPEND WIRESHARK_QT_SRC
			../qt/remote_capture_dialog.cpp
			../qt/remote_settings_dialog.cpp
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
	${CMAKE_CURRENT_SOURCE_DIR}/../qt/expert_info_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../qt/funnel_statistics.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../qt/io_graph_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/../qt/stats_tree_dialog.cpp
	${WIRESHARK_CUSTOM_TAP_SRC}
)

set (LOGRAY_QT_TAP_SRC ${WIRESHARK_QT_TAP_SRC})

set(WIRESHARK_QT_FILES
	${WIRESHARK_QT_SRC}
	${WIRESHARK_QT_TAP_SRC}
)

set (LOGRAY_QT_FILES ${WIRESHARK_QT_FILES})

set(WIRESHARK_QT_UI
	../qt/about_dialog.ui
	../qt/address_editor_frame.ui
	../qt/capture_file_properties_dialog.ui
	../qt/capture_info_dialog.ui
	../qt/capture_options_dialog.ui
	../qt/capture_preferences_frame.ui
	../qt/coloring_rules_dialog.ui
	../qt/column_editor_frame.ui
	../qt/column_preferences_frame.ui
	../qt/compiled_filter_output.ui
	../qt/conversation_hash_tables_dialog.ui
	../qt/decode_as_dialog.ui
	../qt/display_filter_expression_dialog.ui
	../qt/dissector_tables_dialog.ui
	../qt/enabled_protocols_dialog.ui
	../qt/expert_info_dialog.ui
	../qt/export_object_dialog.ui
	../qt/export_pdu_dialog.ui
	../qt/extcap_options_dialog.ui
	../qt/file_set_dialog.ui
	../qt/filter_dialog.ui
	../qt/filter_expression_frame.ui
	../qt/follow_stream_dialog.ui
	../qt/font_color_preferences_frame.ui
	../qt/funnel_string_dialog.ui
	../qt/funnel_text_dialog.ui
	../qt/import_text_dialog.ui
	../qt/interface_frame.ui
	../qt/interface_toolbar.ui
	../qt/io_graph_dialog.ui
	../qt/layout_preferences_frame.ui
	../qt/main_window_preferences_frame.ui
	../qt/manage_interfaces_dialog.ui
	../qt/module_preferences_scroll_area.ui
	../qt/packet_comment_dialog.ui
	../qt/packet_dialog.ui
	../qt/packet_format_group_box.ui
	../qt/packet_range_group_box.ui
	../qt/preference_editor_frame.ui
	../qt/preferences_dialog.ui
	../qt/print_dialog.ui
	../qt/profile_dialog.ui
	../qt/progress_frame.ui
	../qt/protocol_hierarchy_dialog.ui
	../qt/resolved_addresses_dialog.ui
	../qt/rsa_keys_frame.ui
	../qt/search_frame.ui
	# XXX Depends on RTP Stream Dialog
	# ../qt/sequence_dialog.ui
	../qt/show_packet_bytes_dialog.ui
	../qt/supported_protocols_dialog.ui
	../qt/tap_parameter_dialog.ui
	../qt/tcp_stream_dialog.ui
	../qt/time_shift_dialog.ui
	../qt/traffic_table_dialog.ui
	../qt/uat_dialog.ui
	../qt/uat_frame.ui
	../qt/welcome_page.ui
	../qt/widgets/splash_overlay.ui
)

if(HAVE_PCAP_REMOTE)
	list(APPEND WIRESHARK_QT_UI
		../qt/remote_capture_dialog.ui
		../qt/remote_settings_dialog.ui
	)
endif()

set (LOGRAY_QT_UI
	logray_main_window.ui
	${WIRESHARK_QT_UI}
)

set(WIRESHARK_QT_TS
	../qt/wireshark_de.ts
	../qt/wireshark_en.ts # lupdate -pluralonly
	../qt/wireshark_es.ts
	../qt/wireshark_fr.ts
	../qt/wireshark_it.ts
	../qt/wireshark_ja_JP.ts
	../qt/wireshark_pl.ts
	../qt/wireshark_ru.ts
	../qt/wireshark_sv.ts
	../qt/wireshark_tr_TR.ts
	../qt/wireshark_uk.ts
	../qt/wireshark_zh_CN.ts
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
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/i18n.qrc.in ${CMAKE_CURRENT_BINARY_DIR}/i18n.qrc)

set(LOGRAY_QT_QRC
	../../resources/about.qrc
	../../resources/languages/languages.qrc
	../../resources/layout.qrc
	../../resources/lricon.qrc
	../../resources/stock_icons.qrc
	${CMAKE_CURRENT_BINARY_DIR}/i18n.qrc
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
		# QT_INCLUDE_DIRS in the top-level CMakeLists.txt
		# Basically, qt@5 headers should be prioritized over qt@6 which
		# would be found due to GCRYPT_INCLUDE_DIRS=/usr/local/include
		${QT_INCLUDE_DIRS}
		${GCRYPT_INCLUDE_DIRS}
		${MINIZIP_INCLUDE_DIRS}
		${PCAP_INCLUDE_DIRS}
		${SPEEXDSP_INCLUDE_DIRS}
		${WINSPARKLE_INCLUDE_DIRS}
	PRIVATE
		${CMAKE_CURRENT_BINARY_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}/../qt
)

target_compile_definitions(ui_logray
	PUBLIC
		${QT_COMPILE_DEFINITIONS}
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
