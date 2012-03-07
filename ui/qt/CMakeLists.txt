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

# All .h files which inherit from QObject aka which use the Q_OBJECT macro
# need to go here.
set(QTSHARK_H_SRC
	byte_view_tab.h
	byte_view_text.h
	capture_file_dialog.h
	capture_info_dialog.h
	capture_interface_dialog.h
	color_dialog.h
	color_utils.h
	display_filter_combo.h
	display_filter_edit.h
	fileset_dialog.h
	interface_tree.h
	label_stack.h
	main_status_bar.h
	main_welcome.h
	main_window.h
	monospace_font.h
	packet_list.h
	packet_list_model.h
	progress_dialog.h
	proto_tree.h
	recent_file_status.h
	simple_dialog_qt.h
	wireshark_application.h

	# No Q_OBJECT:
	# packet_list_record.h
	# qt_ui_utils.h
)

set(QTSHARK_CPP_SRC
	byte_view_tab.cpp
	byte_view_text.cpp
	capture_file_dialog.cpp
	capture_info_dialog.cpp
	capture_interface_dialog.cpp
	color_dialog.cpp
	color_utils.cpp
	display_filter_combo.cpp
	display_filter_edit.cpp
	fileset_dialog.cpp
	interface_tree.cpp
	label_stack.cpp
	main.cpp
	main_status_bar.cpp
	main_welcome.cpp
	main_window.cpp
	monospace_font.cpp
	packet_list.cpp
	packet_list_model.cpp
	packet_list_record.cpp
	progress_dialog.cpp
	proto_tree.cpp
	qt_ui_utils.cpp
	recent_file_status.cpp
	simple_dialog_qt.cpp
	wireshark_application.cpp
)

set(QTSHARK_SRC
	${QTSHARK_CPP_SRC}
)

set(QTSHARK_UI
	main_window.ui
)

set(QTSHARK_QRC
	display_filter.qrc
	i18n.qrc
	toolbar.qrc
	welcome.qrc
)

set(QTSHARK_TS
	qtshark_fr.ts
)

include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
)

QT4_ADD_TRANSLATION(QTSHARK_TS_QM ${QTSHARK_TS})

QT4_ADD_RESOURCES(QTSHARK_QRC_SRC ${QTSHARK_QRC})

QT4_WRAP_UI(QTSHARK_UI_SRC ${QTSHARK_UI})

# For now, do the moc stuff manually
QT4_WRAP_CPP(QTSHARK_MOC_SRC ${QTSHARK_H_SRC})
# Starting with cmake 2.8.6, we may also use
# set(CMAKE_AUTOMOC TRUE)
# or
# set_target_properties(${some-source-files} PROPERTIES AUTOMOC TRUE)

set(CLEAN_FILES
	# It's too early to care about clean files
	# ${QTSHARK_SRC}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

ADD_DEFINITIONS(${QT_DEFINITIONS})

add_library(qtui STATIC
	${QTSHARK_SRC}
	${QTSHARK_UI_SRC}
	${QTSHARK_MOC_SRC}
	${QTSHARK_QRC_SRC}
	${QTSHARK_TS_QM}
)
set_target_properties(qtui PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

#install(
#	DIRECTORY
#		.
#	DIRECTORY_PERMISSIONS
#		OWNER_EXECUTE OWNER_WRITE OWNER_READ
#		GROUP_EXECUTE GROUP_READ
#		WORLD_EXECUTE WORLD_READ
#	DESTINATION
#		${CMAKE_INSTALL_DATADIR}/${CPACK_PACKAGE_NAME}
#)

#install(TARGETS ui
#	LIBRARY DESTINATION lib
#	RUNTIME DESTINATION lib
#	ARCHIVE DESTINATION lib
#)

