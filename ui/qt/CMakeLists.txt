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

# All .h files which inherit from QObject aka which use the Q_OBJECT macro
# need to go here.
set(QTSHARK_H_SRC
	accordion_frame.h
	byte_view_tab.h
	byte_view_text.h
	capture_file_dialog.h
	capture_filter_combo.h
	capture_filter_edit.h
	capture_filter_syntax_worker.h
	capture_info_dialog.h
	capture_interface_dialog.h
	capture_preferences_frame.h
	color_dialog.h
	color_utils.h
	column_preferences_frame.h
	display_filter_combo.h
	display_filter_edit.h
	elided_label.h
	export_dissection_dialog.h
	export_object_dialog.h
	file_set_dialog.h
	filter_expressions_preferences_frame.h
	follow_stream_dialog.h
	font_color_preferences_frame.h
	import_text_dialog.h
	interface_tree.h
	label_stack.h
	layout_preferences_frame.h
	main_status_bar.h
	main_welcome.h
	main_window.h
	main_window_preferences_frame.h
	module_preferences_scroll_area.h
	packet_comment_dialog.h
	packet_format_group_box.h
	packet_list.h
	packet_list_model.h
	packet_range_group_box.h
	preferences_dialog.h
	print_dialog.h
	profile_dialog.h
	progress_bar.h
	proto_tree.h
	qcustomplot.h
	recent_file_status.h
	search_frame.h
	sequence_diagram.h
	sequence_dialog.h
	simple_dialog_qt.h
	splash_overlay.h
	summary_dialog.h
	syntax_line_edit.h
	tcp_stream_dialog.h
	time_shift_dialog.h
	uat_dialog.h
	wireshark_application.h

	# No Q_OBJECT:
	# packet_list_record.h
	# qt_ui_utils.h
	# related_packet_delegate.h
	# sparkline_delegate.h
)

set(CLEAN_FILES
	accordion_frame.cpp
	byte_view_tab.cpp
	byte_view_text.cpp
	capture_file_dialog.cpp
	capture_filter_combo.cpp
	capture_filter_edit.cpp
	capture_filter_syntax_worker.cpp
	capture_info_dialog.cpp
	capture_interface_dialog.cpp
	color_dialog.cpp
	color_utils.cpp
	capture_preferences_frame.cpp
	column_preferences_frame.cpp
	display_filter_combo.cpp
	display_filter_edit.cpp
	elided_label.cpp
	export_dissection_dialog.cpp
	export_object_dialog.cpp
	file_set_dialog.cpp
	filter_expressions_preferences_frame.cpp
	follow_stream_dialog.cpp
	font_color_preferences_frame.cpp
	import_text_dialog.cpp
	interface_tree.cpp
	label_stack.cpp
	layout_preferences_frame.cpp
	main.cpp
	main_status_bar.cpp
	main_welcome.cpp
	main_window.cpp
	main_window_preferences_frame.cpp
	main_window_slots.cpp
	module_preferences_scroll_area.cpp
	packet_comment_dialog.cpp
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
	qt_ui_utils.cpp
	recent_file_status.cpp
	related_packet_delegate.cpp
	search_frame.cpp
	sequence_diagram.cpp
	sequence_dialog.cpp
	simple_dialog_qt.cpp
	splash_overlay.cpp
	sparkline_delegate.cpp
	summary_dialog.cpp
	syntax_line_edit.cpp
	tcp_stream_dialog.cpp
	time_shift_dialog.cpp
	uat_dialog.cpp
	wireshark_application.cpp
)

set(DIRTY_FILES
	qcustomplot.cpp
)

set(QTSHARK_UI
	capture_preferences_frame.ui
	column_preferences_frame.ui
	export_object_dialog.ui
	file_set_dialog.ui
	filter_expressions_preferences_frame.ui
	follow_stream_dialog.ui
	font_color_preferences_frame.ui
	import_text_dialog.ui
	layout_preferences_frame.ui
	main_welcome.ui
	main_window.ui
	main_window_preferences_frame.ui
	module_preferences_scroll_area.ui
	packet_comment_dialog.ui
	packet_format_group_box.ui
	packet_range_group_box.ui
	preferences_dialog.ui
	print_dialog.ui
	profile_dialog.ui
	search_frame.ui
	sequence_dialog.ui
	splash_overlay.ui
	summary_dialog.ui
	tcp_stream_dialog.ui
	time_shift_dialog.ui
	uat_dialog.ui
)

set(QTSHARK_QRC
	../../image/display_filter.qrc
	../../image/layout.qrc
	../../image/status.qrc
	../../image/toolbar.qrc
	i18n.qrc
	welcome.qrc
)

set(QTSHARK_TS
	qtshark_de.ts
	qtshark_fr.ts
	qtshark_zh_CN.ts
)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_BINARY_DIR}
)

if (QT_VERSION EQUAL 5)
	QT5_ADD_TRANSLATION(QTSHARK_TS_QM ${QTSHARK_TS})
	QT5_ADD_RESOURCES(QTSHARK_QRC_SRC ${QTSHARK_QRC})
	QT5_WRAP_UI(QTSHARK_UI_SRC ${QTSHARK_UI})
	# For now, do the moc stuff manually
	QT5_WRAP_CPP(QTSHARK_MOC_SRC ${QTSHARK_H_SRC})
	# Starting with cmake 2.8.6, we may also use
	# set(CMAKE_AUTOMOC TRUE)
	# or
	# set_target_properties(${some-source-files} PROPERTIES AUTOMOC TRUE)
else()
	QT4_ADD_TRANSLATION(QTSHARK_TS_QM ${QTSHARK_TS})
	QT4_ADD_RESOURCES(QTSHARK_QRC_SRC ${QTSHARK_QRC})
	QT4_WRAP_UI(QTSHARK_UI_SRC ${QTSHARK_UI})
	# For now, do the moc stuff manually
	QT4_WRAP_CPP(QTSHARK_MOC_SRC ${QTSHARK_H_SRC})
	# Starting with cmake 2.8.6, we may also use
	# set(CMAKE_AUTOMOC TRUE)
	# or
	# set_target_properties(${some-source-files} PROPERTIES AUTOMOC TRUE)
endif()

set(QTSHARK_SRC
	${CLEAN_FILES}
	${DIRTY_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
	# The Qt headers generate a ton of shortening errors on 64-bit systems.
	if (CMAKE_SIZEOF_VOID_P EQUAL 8)
		set_source_files_properties(
			${CLEAN_FILES}
			PROPERTIES
			COMPILE_FLAGS -Wno-shorten-64-to-32
		)
	endif()
endif()

add_definitions(${QT_DEFINITIONS})

add_library(qtui STATIC
	${QTSHARK_SRC}
	${QTSHARK_UI_SRC}
	${QTSHARK_MOC_SRC}
	${QTSHARK_QRC_SRC}
	${QTSHARK_TS_QM}
)
set_target_properties(qtui PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(qtui PROPERTIES FOLDER "UI")

