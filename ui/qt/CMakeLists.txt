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
	widgets/additional_toolbar.h
	widgets/apply_line_edit.h
	widgets/byte_view_text.h
	widgets/capture_filter_combo.h
	widgets/capture_filter_edit.h
	widgets/clickable_label.h
	widgets/copy_from_profile_button.h
	widgets/detachable_tabwidget.h
	widgets/display_filter_combo.h
	widgets/display_filter_edit.h
	widgets/dissector_tables_view.h
	widgets/drag_drop_toolbar.h
	widgets/drag_label.h
	widgets/editor_file_dialog.h
	widgets/elided_label.h
	widgets/expert_info_view.h
	widgets/export_objects_view.h
	widgets/field_filter_edit.h
	widgets/filter_expression_toolbar.h
	widgets/find_line_edit.h
	widgets/follow_stream_text.h
	widgets/interface_toolbar_lineedit.h
	widgets/label_stack.h
	widgets/overlay_scroll_bar.h
	widgets/packet_list_header.h
	widgets/path_selection_edit.h
	widgets/pref_module_view.h
	widgets/profile_tree_view.h
	widgets/range_syntax_lineedit.h
	widgets/rtp_audio_graph.h
	widgets/splash_overlay.h
	widgets/stock_icon_tool_button.h
	widgets/syntax_line_edit.h
	widgets/tabnav_tree_view.h
	widgets/traffic_tab.h
	widgets/traffic_tree.h
	widgets/traffic_types_list.h
	widgets/wireless_timeline.h
	widgets/wireshark_file_dialog.h
)

set(WIRESHARK_3RD_PARTY_WIDGET_HEADERS
	widgets/qcustomplot.h
)

set(WIRESHARK_MANAGER_HEADERS
	manager/preference_manager.h
	manager/wireshark_preference.h
)

set(WIRESHARK_UTILS_HEADERS
	utils/color_utils.h
	utils/data_printer.h
	utils/field_information.h
	utils/frame_information.h
	utils/idata_printable.h
	utils/proto_node.h
	utils/qt_ui_utils.h
	utils/rtp_audio_file.h
	utils/rtp_audio_routing_filter.h
	utils/rtp_audio_routing.h
	utils/rtp_audio_silence_generator.h
	utils/stock_icon.h
	utils/tango_colors.h
	utils/variant_pointer.h
	utils/wireshark_mime_data.h
	utils/wireshark_zip_helper.h
)

set(WIRESHARK_MODEL_HEADERS
	models/astringlist_list_model.h
	models/atap_data_model.h
	models/cache_proxy_model.h
	models/coloring_rules_delegate.h
	models/coloring_rules_model.h
	models/column_list_model.h
	models/credentials_model.h
	models/decode_as_delegate.h
	models/decode_as_model.h
	models/dissector_tables_model.h
	models/enabled_protocols_model.h
	models/expert_info_model.h
	models/expert_info_proxy_model.h
	models/export_objects_model.h
	models/fileset_entry_model.h
	models/filter_list_model.h
	models/info_proxy_model.h
	models/interface_sort_filter_model.h
	models/interface_tree_cache_model.h
	models/interface_tree_model.h
	models/numeric_value_chooser_delegate.h
	models/packet_list_model.h
	models/packet_list_record.h
	models/path_selection_delegate.h
	models/percent_bar_delegate.h
	models/pref_delegate.h
	models/pref_models.h
	models/profile_model.h
	models/proto_tree_model.h
	models/related_packet_delegate.h
	models/resolved_addresses_models.h
	models/sparkline_delegate.h
	models/supported_protocols_model.h
	models/timeline_delegate.h
	models/tree_model_helpers.h
	models/uat_delegate.h
	models/uat_model.h
	models/url_link_delegate.h
	models/voip_calls_info_model.h
)

# All .h files which inherit from QObject aka which use the Q_OBJECT macro
# need to go here.
set(WIRESHARK_QT_HEADERS
	about_dialog.h
	accordion_frame.h
	address_editor_frame.h
	bluetooth_att_server_attributes_dialog.h
	bluetooth_device_dialog.h
	bluetooth_devices_dialog.h
	bluetooth_hci_summary_dialog.h
	byte_view_tab.h
	capture_file_dialog.h
	capture_file_properties_dialog.h
	capture_file.h
	capture_filter_syntax_worker.h
	capture_options_dialog.h
	capture_preferences_frame.h
	coloring_rules_dialog.h
	column_editor_frame.h
	column_preferences_frame.h
	compiled_filter_output.h
	conversation_colorize_action.h
	conversation_dialog.h
	conversation_hash_tables_dialog.h
	credentials_dialog.h
	decode_as_dialog.h
	display_filter_expression_dialog.h
	dissector_tables_dialog.h
	enabled_protocols_dialog.h
	endpoint_dialog.h
	expert_info_dialog.h
	export_dissection_dialog.h
	export_object_action.h
	export_object_dialog.h
	export_pdu_dialog.h
	extcap_argument_file.h
	extcap_argument_multiselect.h
	extcap_argument.h
	extcap_options_dialog.h
	file_set_dialog.h
	filter_action.h
	filter_dialog.h
	filter_dialog.h
	filter_expression_frame.h
	firewall_rules_dialog.h
	follow_stream_dialog.h
	font_color_preferences_frame.h
	funnel_statistics.h
	funnel_string_dialog.h
	funnel_text_dialog.h
	geometry_state_dialog.h
	gsm_map_summary_dialog.h
	iax2_analysis_dialog.h
	import_text_dialog.h
	interface_frame.h
	interface_toolbar_reader.h
	interface_toolbar.h
	io_graph_dialog.h
	layout_preferences_frame.h
	lbm_lbtrm_transport_dialog.h
	lbm_lbtru_transport_dialog.h
	lbm_stream_dialog.h
	lte_mac_statistics_dialog.h
	lte_rlc_graph_dialog.h
	lte_rlc_statistics_dialog.h
	main_application.h
	main_status_bar.h
	main_window_preferences_frame.h
	main_window.h
	manage_interfaces_dialog.h
	module_preferences_scroll_area.h
	mtp3_summary_dialog.h
	multicast_statistics_dialog.h
	packet_comment_dialog.h
	packet_diagram.h
	packet_dialog.h
	packet_format_group_box.h
	packet_list.h
	packet_range_group_box.h
	preference_editor_frame.h
	preferences_dialog.h
	print_dialog.h
	profile_dialog.h
	progress_frame.h
	proto_tree.h
	protocol_hierarchy_dialog.h
	protocol_preferences_menu.h
	recent_file_status.h
	resolved_addresses_dialog.h
	response_time_delay_dialog.h
	rpc_service_response_time_dialog.h
	rsa_keys_frame.h
	rtp_analysis_dialog.h
	rtp_audio_stream.h
	rtp_player_dialog.h
	rtp_stream_dialog.h
	scsi_service_response_time_dialog.h
	sctp_all_assocs_dialog.h
	sctp_assoc_analyse_dialog.h
	sctp_chunk_statistics_dialog.h
	sctp_graph_arwnd_dialog.h
	sctp_graph_byte_dialog.h
	sctp_graph_dialog.h
	search_frame.h
	sequence_diagram.h
	sequence_dialog.h
	service_response_time_dialog.h
	show_packet_bytes_dialog.h
	simple_statistics_dialog.h
	stats_tree_dialog.h
	strip_headers_dialog.h
	supported_protocols_dialog.h
	tabnav_tree_widget.h
	tap_parameter_dialog.h
	tcp_stream_dialog.h
	time_shift_dialog.h
	traffic_table_dialog.h
	uat_dialog.h
	uat_frame.h
	voip_calls_dialog.h
	welcome_page.h
	wireless_frame.h
	wireshark_application.h
	wireshark_dialog.h
	wireshark_main_window.h
	wlan_statistics_dialog.h
	${WIRESHARK_CUSTOM_QT_HEADERS}
)

if(ENABLE_PCAP)
	list(APPEND WIRESHARK_QT_HEADERS
		capture_info_dialog.h
	)
	if(HAVE_PCAP_REMOTE)
		list(APPEND WIRESHARK_QT_HEADERS
			remote_capture_dialog.h
			remote_settings_dialog.h
		)
	endif()
endif()

set(WIRESHARK_WIDGET_SRCS
	widgets/additional_toolbar.cpp
	widgets/apply_line_edit.cpp
	widgets/byte_view_text.cpp
	widgets/capture_filter_combo.cpp
	widgets/capture_filter_edit.cpp
	widgets/clickable_label.cpp
	widgets/copy_from_profile_button.cpp
	widgets/detachable_tabwidget.cpp
	widgets/display_filter_combo.cpp
	widgets/display_filter_edit.cpp
	widgets/dissector_tables_view.cpp
	widgets/drag_drop_toolbar.cpp
	widgets/drag_label.cpp
	widgets/editor_file_dialog.cpp
	widgets/elided_label.cpp
	widgets/expert_info_view.cpp
	widgets/export_objects_view.cpp
	widgets/field_filter_edit.cpp
	widgets/filter_expression_toolbar.cpp
	widgets/find_line_edit.cpp
	widgets/follow_stream_text.cpp
	widgets/interface_toolbar_lineedit.cpp
	widgets/label_stack.cpp
	widgets/overlay_scroll_bar.cpp
	widgets/packet_list_header.cpp
	widgets/path_selection_edit.cpp
	widgets/pref_module_view.cpp
	widgets/profile_tree_view.cpp
	widgets/range_syntax_lineedit.cpp
	widgets/rtp_audio_graph.cpp
	widgets/splash_overlay.cpp
	widgets/stock_icon_tool_button.cpp
	widgets/syntax_line_edit.cpp
	widgets/tabnav_tree_view.cpp
	widgets/traffic_tab.cpp
	widgets/traffic_tree.cpp
	widgets/traffic_types_list.cpp
	widgets/wireless_timeline.cpp
	widgets/wireshark_file_dialog.cpp
)

set(WIRESHARK_3RD_PARTY_WIDGET_SRCS
	widgets/qcustomplot.cpp
)

set(WIRESHARK_MANAGER_SRCS
	manager/preference_manager.cpp
	manager/wireshark_preference.cpp
)

set(WIRESHARK_UTILS_SRCS
	utils/color_utils.cpp
	utils/data_printer.cpp
	utils/field_information.cpp
	utils/frame_information.cpp
	utils/proto_node.cpp
	utils/qt_ui_utils.cpp
	utils/rtp_audio_file.cpp
	utils/rtp_audio_routing_filter.cpp
	utils/rtp_audio_routing.cpp
	utils/rtp_audio_silence_generator.cpp
	utils/stock_icon.cpp
	utils/wireshark_mime_data.cpp
	utils/wireshark_zip_helper.cpp
)

set(WIRESHARK_MODEL_SRCS
	models/astringlist_list_model.cpp
	models/atap_data_model.cpp
	models/cache_proxy_model.cpp
	models/coloring_rules_delegate.cpp
	models/coloring_rules_model.cpp
	models/column_list_model.cpp
	models/credentials_model.cpp
	models/decode_as_delegate.cpp
	models/decode_as_model.cpp
	models/dissector_tables_model.cpp
	models/enabled_protocols_model.cpp
	models/expert_info_model.cpp
	models/expert_info_proxy_model.cpp
	models/export_objects_model.cpp
	models/fileset_entry_model.cpp
	models/filter_list_model.cpp
	models/info_proxy_model.cpp
	models/interface_sort_filter_model.cpp
	models/interface_tree_cache_model.cpp
	models/interface_tree_model.cpp
	models/numeric_value_chooser_delegate.cpp
	models/packet_list_model.cpp
	models/packet_list_record.cpp
	models/path_selection_delegate.cpp
	models/percent_bar_delegate.cpp
	models/pref_delegate.cpp
	models/pref_models.cpp
	models/profile_model.cpp
	models/proto_tree_model.cpp
	models/related_packet_delegate.cpp
	models/resolved_addresses_models.cpp
	models/sparkline_delegate.cpp
	models/supported_protocols_model.cpp
	models/timeline_delegate.cpp
	models/uat_delegate.cpp
	models/uat_model.cpp
	models/url_link_delegate.cpp
	models/voip_calls_info_model.cpp
)

set(WIRESHARK_QT_SRC
	about_dialog.cpp
	accordion_frame.cpp
	address_editor_frame.cpp
	bluetooth_att_server_attributes_dialog.cpp
	bluetooth_device_dialog.cpp
	bluetooth_devices_dialog.cpp
	bluetooth_hci_summary_dialog.cpp
	byte_view_tab.cpp
	capture_file_dialog.cpp
	capture_file_properties_dialog.cpp
	capture_file.cpp
	capture_filter_syntax_worker.cpp
	capture_options_dialog.cpp
	capture_preferences_frame.cpp
	coloring_rules_dialog.cpp
	column_editor_frame.cpp
	column_preferences_frame.cpp
	compiled_filter_output.cpp
	conversation_colorize_action.cpp
	conversation_dialog.cpp
	conversation_hash_tables_dialog.cpp
	credentials_dialog.cpp
	decode_as_dialog.cpp
	display_filter_expression_dialog.cpp
	dissector_tables_dialog.cpp
	enabled_protocols_dialog.cpp
	endpoint_dialog.cpp
	export_dissection_dialog.cpp
	export_object_action.cpp
	export_object_dialog.cpp
	export_pdu_dialog.cpp
	extcap_argument_file.cpp
	extcap_argument_multiselect.cpp
	extcap_argument.cpp
	extcap_options_dialog.cpp
	file_set_dialog.cpp
	filter_action.cpp
	filter_dialog.cpp
	filter_expression_frame.cpp
	firewall_rules_dialog.cpp
	follow_stream_dialog.cpp
	font_color_preferences_frame.cpp
	funnel_string_dialog.cpp
	funnel_text_dialog.cpp
	geometry_state_dialog.cpp
	iax2_analysis_dialog.cpp
	import_text_dialog.cpp
	interface_frame.cpp
	interface_toolbar_reader.cpp
	interface_toolbar.cpp
	layout_preferences_frame.cpp
	lbm_lbtrm_transport_dialog.cpp
	lbm_lbtru_transport_dialog.cpp
	lbm_stream_dialog.cpp
	lte_mac_statistics_dialog.cpp
	lte_rlc_graph_dialog.cpp
	lte_rlc_statistics_dialog.cpp
	main_application.cpp
	main_status_bar.cpp
	main_window_layout.cpp
	main_window_preferences_frame.cpp
	main_window.cpp
	main.cpp
	manage_interfaces_dialog.cpp
	module_preferences_scroll_area.cpp
	packet_comment_dialog.cpp
	packet_diagram.cpp
	packet_dialog.cpp
	packet_format_group_box.cpp
	packet_list.cpp
	packet_range_group_box.cpp
	preference_editor_frame.cpp
	preferences_dialog.cpp
	print_dialog.cpp
	profile_dialog.cpp
	progress_frame.cpp
	proto_tree.cpp
	protocol_hierarchy_dialog.cpp
	protocol_preferences_menu.cpp
	recent_file_status.cpp
	resolved_addresses_dialog.cpp
	response_time_delay_dialog.cpp
	rpc_service_response_time_dialog.cpp
	rsa_keys_frame.cpp
	rtp_analysis_dialog.cpp
	rtp_audio_stream.cpp
	rtp_player_dialog.cpp
	rtp_stream_dialog.cpp
	scsi_service_response_time_dialog.cpp
	sctp_all_assocs_dialog.cpp
	sctp_assoc_analyse_dialog.cpp
	sctp_chunk_statistics_dialog.cpp
	sctp_graph_arwnd_dialog.cpp
	sctp_graph_byte_dialog.cpp
	sctp_graph_dialog.cpp
	search_frame.cpp
	sequence_diagram.cpp
	sequence_dialog.cpp
	service_response_time_dialog.cpp
	show_packet_bytes_dialog.cpp
	simple_dialog.cpp
	simple_statistics_dialog.cpp
	supported_protocols_dialog.cpp
	strip_headers_dialog.cpp
	tabnav_tree_widget.cpp
	tap_parameter_dialog.cpp
	tcp_stream_dialog.cpp
	time_shift_dialog.cpp
	traffic_table_dialog.cpp
	uat_dialog.cpp
	uat_frame.cpp
	voip_calls_dialog.cpp
	welcome_page.cpp
	wireless_frame.cpp
	wireshark_application.cpp
	wireshark_dialog.cpp
	wireshark_main_window.cpp
	wireshark_main_window_slots.cpp
	${WIRESHARK_CUSTOM_QT_SRCS}
)

if(ENABLE_PCAP)
	list(APPEND WIRESHARK_QT_SRC
		capture_info_dialog.cpp
	)
	if(HAVE_PCAP_REMOTE)
		list(APPEND WIRESHARK_QT_SRC
			remote_capture_dialog.cpp
			remote_settings_dialog.cpp
		)
	endif()
endif()

set(WIRESHARK_QT_TAP_SRC
	${CMAKE_CURRENT_SOURCE_DIR}/expert_info_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/funnel_statistics.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/gsm_map_summary_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/io_graph_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/lte_mac_statistics_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/lte_rlc_statistics_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/mtp3_summary_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/multicast_statistics_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/rtp_stream_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/sctp_all_assocs_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/sctp_assoc_analyse_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/stats_tree_dialog.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/wlan_statistics_dialog.cpp
	${WIRESHARK_CUSTOM_TAP_SRC}
)

set(WIRESHARK_QT_FILES
	${WIRESHARK_QT_SRC}
	${WIRESHARK_QT_TAP_SRC}
)

set(WIRESHARK_QT_UI
	about_dialog.ui
	address_editor_frame.ui
	bluetooth_att_server_attributes_dialog.ui
	bluetooth_device_dialog.ui
	bluetooth_devices_dialog.ui
	bluetooth_hci_summary_dialog.ui
	capture_file_properties_dialog.ui
	capture_info_dialog.ui
	capture_options_dialog.ui
	capture_preferences_frame.ui
	coloring_rules_dialog.ui
	column_editor_frame.ui
	column_preferences_frame.ui
	compiled_filter_output.ui
	conversation_hash_tables_dialog.ui
	credentials_dialog.ui
	decode_as_dialog.ui
	display_filter_expression_dialog.ui
	dissector_tables_dialog.ui
	enabled_protocols_dialog.ui
	expert_info_dialog.ui
	export_object_dialog.ui
	export_pdu_dialog.ui
	extcap_options_dialog.ui
	file_set_dialog.ui
	filter_dialog.ui
	filter_expression_frame.ui
	firewall_rules_dialog.ui
	follow_stream_dialog.ui
	font_color_preferences_frame.ui
	funnel_string_dialog.ui
	funnel_text_dialog.ui
	gsm_map_summary_dialog.ui
	iax2_analysis_dialog.ui
	import_text_dialog.ui
	interface_frame.ui
	interface_toolbar.ui
	io_graph_dialog.ui
	layout_preferences_frame.ui
	lbm_lbtrm_transport_dialog.ui
	lbm_lbtru_transport_dialog.ui
	lbm_stream_dialog.ui
	lte_rlc_graph_dialog.ui
	main_window_preferences_frame.ui
	manage_interfaces_dialog.ui
	module_preferences_scroll_area.ui
	mtp3_summary_dialog.ui
	packet_comment_dialog.ui
	packet_dialog.ui
	packet_format_group_box.ui
	packet_range_group_box.ui
	preference_editor_frame.ui
	preferences_dialog.ui
	print_dialog.ui
	profile_dialog.ui
	progress_frame.ui
	protocol_hierarchy_dialog.ui
	resolved_addresses_dialog.ui
	rsa_keys_frame.ui
	rtp_analysis_dialog.ui
	rtp_player_dialog.ui
	rtp_stream_dialog.ui
	sctp_all_assocs_dialog.ui
	sctp_assoc_analyse_dialog.ui
	sctp_chunk_statistics_dialog.ui
	sctp_graph_arwnd_dialog.ui
	sctp_graph_byte_dialog.ui
	sctp_graph_dialog.ui
	search_frame.ui
	sequence_dialog.ui
	show_packet_bytes_dialog.ui
	strip_headers_dialog.ui
	supported_protocols_dialog.ui
	tap_parameter_dialog.ui
	tcp_stream_dialog.ui
	time_shift_dialog.ui
	traffic_table_dialog.ui
	uat_dialog.ui
	uat_frame.ui
	voip_calls_dialog.ui
	welcome_page.ui
	widgets/splash_overlay.ui
	wireless_frame.ui
	wireshark_main_window.ui
)

if(HAVE_PCAP_REMOTE)
	list(APPEND WIRESHARK_QT_UI
		remote_capture_dialog.ui
		remote_settings_dialog.ui
	)
endif()

set(WIRESHARK_QT_TS
	wireshark_de.ts
	wireshark_en.ts # lupdate -pluralonly
	wireshark_es.ts
	wireshark_fr.ts
	wireshark_it.ts
	wireshark_ja_JP.ts
	wireshark_pl.ts
	wireshark_ru.ts
	wireshark_sv.ts
	wireshark_tr_TR.ts
	wireshark_uk.ts
	wireshark_zh_CN.ts
)

foreach(_file ${WIRESHARK_QT_TS})
	get_filename_component(_qresource ${_file} NAME_WE)
	set(_qresource_qm "${_qresource}.qm")
	set(i18n_qresource "${i18n_qresource}\n    <file>${_qresource_qm}</file>")
endforeach()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/i18n.qrc.in ${CMAKE_CURRENT_BINARY_DIR}/i18n.qrc)

set(WIRESHARK_QT_QRC
	../../resources/about.qrc
	../../resources/languages/languages.qrc
	../../resources/layout.qrc
	../../resources/stock_icons.qrc
	../../resources/wsicon.qrc
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
	QT6_ADD_TRANSLATION(WIRESHARK_QT_QM ${WIRESHARK_QT_TS} OPTIONS -silent)
elseif(NOT Qt${qtver}Widgets_VERSION VERSION_LESS "5.11")
	QT5_ADD_TRANSLATION(WIRESHARK_QT_QM ${WIRESHARK_QT_TS} OPTIONS -silent)
else()
	QT5_ADD_TRANSLATION(WIRESHARK_QT_QM ${WIRESHARK_QT_TS})
endif()

add_custom_target(
	translations
	DEPENDS
		${WIRESHARK_QT_QM}
)
set_target_properties(translations PROPERTIES FOLDER "UI")

set_source_files_properties(
	${WIRESHARK_QT_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

set_source_files_properties(
	wireshark-tap-register.c
	PROPERTIES
	SKIP_AUTOGEN ON
)

add_definitions(${QT_DEFINITIONS})

register_tap_files(wireshark-tap-register.c
	${WIRESHARK_QT_TAP_SRC}
)

source_group("ui\\UIC Files" FILES ${WIRESHARK_QT_UI})
source_group("ui\\qrc" FILES ${WIRESHARK_QT_QRC})
source_group("ui\\Header" FILES ${WIRESHARK_QT_HEADERS})
source_group("ui\\Widget Header" FILES ${WIRESHARK_WIDGET_HEADERS})
source_group("ui\\Widget Source" FILES ${WIRESHARK_WIDGET_SRCS})
source_group("ui\\Utils Headers Files" FILES ${WIRESHARK_UTILS_HEADERS})
source_group("ui\\Utils Source" FILES ${WIRESHARK_UTILS_SRCS})
source_group("ui\\Models Headers" FILES ${WIRESHARK_MODEL_HEADERS})
source_group("ui\\Models Source" FILES ${WIRESHARK_MODEL_SRCS})
source_group("ui\\Manager Headers" FILES ${WIRESHARK_MANAGER_HEADERS})
source_group("ui\\Manager Source" FILES ${WIRESHARK_MANAGER_SRCS})

add_library(qtui OBJECT
	#Included so that Visual Studio can properly put header files in solution
	${WIRESHARK_QT_HEADERS}
	${WIRESHARK_WIDGET_HEADERS}
	${WIRESHARK_3RD_PARTY_WIDGET_HEADERS}
	${WIRESHARK_MANAGER_HEADERS}
	${WIRESHARK_UTILS_HEADERS}
	${WIRESHARK_MODEL_HEADERS}

	${WIRESHARK_QT_SRC}
	${WIRESHARK_WIDGET_SRCS}
	${WIRESHARK_3RD_PARTY_WIDGET_SRCS}
	${WIRESHARK_MANAGER_SRCS}
	${WIRESHARK_UTILS_SRCS}
	${WIRESHARK_MODEL_SRCS}

	# For AUTOUIC and AUTORCC.
	${WIRESHARK_QT_UI}
	${WIRESHARK_QT_QRC}

	${WIRESHARK_QT_TAP_SRC}
	wireshark-tap-register.c
)

target_include_directories(qtui
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
)

target_compile_definitions(qtui
	PUBLIC
		${QT_COMPILE_DEFINITIONS}
)

set_target_properties(qtui PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "UI"
	AUTOMOC ON
	AUTOUIC ON
	AUTORCC ON
	# Ensure .qm files are generated before autogenerating i18n.qrc
	AUTOGEN_TARGET_DEPENDS "${WIRESHARK_QT_QM}"
)

if(MSVC)
	set_target_properties(qtui PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
endif()

CHECKAPI(
	NAME
		ui-qt
	SWITCHES
		--nocheck-shadow
	SOURCES
		# QCustomPlot (WIRESHARK_3RD_PARTY_WIDGET_{HEADERS,SRCS}) uses
		# prohibited APIs.
		${WIRESHARK_QT_HEADERS}
		${WIRESHARK_WIDGET_HEADERS}
		${WIRESHARK_MANAGER_HEADERS}
		${WIRESHARK_UTILS_HEADERS}
		${WIRESHARK_MODEL_HEADERS}

		${WIRESHARK_QT_SRC}
		${WIRESHARK_WIDGET_SRCS}
		${WIRESHARK_MANAGER_SRCS}
		${WIRESHARK_UTILS_SRCS}
		${WIRESHARK_MODEL_SRCS}
		${WIRESHARK_QT_TAP_SRC}
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
