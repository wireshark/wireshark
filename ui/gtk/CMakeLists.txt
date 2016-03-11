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

ADD_CUSTOM_CMAKE_INCLUDE()

set(WIRESHARK_GTK_SRC
	about_dlg.c
	addr_resolution_dlg.c
	bytes_view.c
	capture_dlg.c
	capture_file_dlg.c
	capture_if_dlg.c
	capture_info_dlg.c
	color_dlg.c
	color_edit_dlg.c
	color_utils.c
	conversation_hastables_dlg.c
	conversations_table.c
	decode_as_dlg.c
	dfilter_expr_dlg.c
	dissector_tables_dlg.c
	dlg_utils.c
	drag_and_drop.c
	edit_packet_comment_dlg.c
	expert_comp_table.c
	export_object_dlg.c
	export_pdu_dlg.c
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
	follow_stream.c
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
	main_filter_toolbar.c
	main_menubar.c
	main_statusbar.c
	main_titlebar.c
	main_toolbar.c
	main_welcome.c
	manual_addr_resolv.c
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
	prefs_font_color.c
	print_dlg.c
	profile_dlg.c
	progress_dlg.c
	proto_dlg.c
	proto_help.c
	proto_hier_stats_dlg.c
	proto_hier_tree_model.c
	proto_tree_model.c
	range_utils.c
	response_time_delay_table.c
	sctp_byte_graph_dlg.c
	sctp_error_dlg.c
	sctp_graph_dlg.c
	service_response_time_table.c
	simple_dialog.c
	simple_stattable.c
	stock_icons.c
	summary_dlg.c
	supported_protos_dlg.c
	tap_param_dlg.c
	text_page_utils.c
	time_shift_dlg.c
	uat_gui.c
	webbrowser.c
	${WIRESHARK_CUSTOM_GTK_SRC}
)

if (AIRPCAP_FOUND)
	set(WIRESHARK_GTK_SRC
		${WIRESHARK_GTK_SRC}
		airpcap_dlg.c
		airpcap_gui_utils.c
		main_airpcap_toolbar.c
	)
endif()

if(PORTAUDIO_FOUND)
	set(WIRESHARK_GTK_SRC
		${WIRESHARK_GTK_SRC}
		rtp_player.c
	)

	# For Win32, there is no PortAudio lib, we compile the files locally
	if(WIN32)
		add_definitions(
			-DPA_NO_DS
			-DPA_NO_ASIO
		)
		set(PORTAUDIO_SRC
			${PORTAUDIO_SRC_DIR}/common/pa_allocation.c
			${PORTAUDIO_SRC_DIR}/common/pa_converters.c
			${PORTAUDIO_SRC_DIR}/common/pa_cpuload.c
			${PORTAUDIO_SRC_DIR}/common/pa_dither.c
			${PORTAUDIO_SRC_DIR}/common/pa_front.c
			${PORTAUDIO_SRC_DIR}/common/pa_process.c
			${PORTAUDIO_SRC_DIR}/common/pa_skeleton.c
			${PORTAUDIO_SRC_DIR}/common/pa_stream.c
			${PORTAUDIO_SRC_DIR}/common/pa_trace.c
			${PORTAUDIO_SRC_DIR}/os/win/pa_win_hostapis.c
			${PORTAUDIO_SRC_DIR}/os/win/pa_win_util.c
			${PORTAUDIO_SRC_DIR}/os/win/pa_x86_plain_converters.c
			${PORTAUDIO_SRC_DIR}/os/win/pa_win_waveformat.c
			${PORTAUDIO_SRC_DIR}/hostapi/wmme/pa_win_wmme.c
		)
		add_library(portaudio OBJECT
			${PORTAUDIO_SRC}
		)
		set_target_properties(portaudio PROPERTIES
			INCLUDE_DIRECTORIES "${PORTAUDIO_INCLUDE_DIRS}"
			FOLDER "UI")

		# Portaudio has some warnings, annoyingly the combination of CMake
		# and MSBuild means that just disabling the warnings on the specific
		# source files doesn't work, so set them to level 4 for the target
		#set_source_files_properties(${PORTAUDIO_SRC_DIR}/common/pa_front.c
		#	PROPERTIES
		#	COMPILE_FLAGS "/wd4189"
		#)
		#set_source_files_properties(${PORTAUDIO_SRC_DIR}/os/win/pa_x86_plain_converters.c
		#	PROPERTIES
		#	COMPILE_FLAGS "/wd4305"
		#)
		target_compile_options(portaudio
			PUBLIC "/w44189"
			PUBLIC "/w44305"
		)

		# Portaudio has some size_t > long warnings as a result of using strlen() on x64.
		if ("${WIRESHARK_TARGET_PLATFORM}" STREQUAL "win64")
			#set_source_files_properties(${PORTAUDIO_SRC_DIR}/hostapi/wmme/pa_win_wmme.c
			#	PROPERTIES
			#	COMPILE_FLAGS "/wd4267"
			#)
			target_compile_options(portaudio
				PUBLIC "/w44267"
			)
		endif()
	endif()
endif()

if(ENABLE_EXTCAP)
	set(WIRESHARK_GTK_SRC
		${WIRESHARK_GTK_SRC}
		extcap_gtk.c
	)
endif()

set(WIRESHARK_TAP_SRC
	compare_stat.c
	dcerpc_stat.c
	expert_comp_dlg.c
	flow_graph.c
	funnel_stat.c
	gsm_map_summary.c
	iax2_analysis.c
	io_stat.c
	lbm_stream_dlg.c
	lbm_uimflow_dlg.c
	mac_lte_stat_dlg.c
	mcast_stream_dlg.c
	mtp3_summary.c
	rlc_lte_graph.c
	rlc_lte_stat_dlg.c
	rpc_stat.c
	rtp_analysis.c
	rtp_stream_dlg.c
	sctp_assoc_analyse.c
	sctp_chunk_stat.c
	sctp_chunk_stat_dlg.c
	sctp_stat_dlg.c
	stats_tree_stat.c
	tcp_graph.c
	voip_calls_dlg.c
	wlan_stat_dlg.c
	${WIRESHARK_CUSTOM_TAP_SRC}
)

set(CLEAN_FILES
	${WIRESHARK_GTK_SRC}
	${WIRESHARK_TAP_SRC}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS "${WERROR_COMMON_FLAGS} ${NO_ERROR_DEPRECATED_DECLARATIONS_COMPILE_FLAGS}"
	)
endif()

if (ENABLE_GTK3)
	add_definitions(
		${GTK3_DEFINITIONS}
		-DGDK_DISABLE_DEPRECATION_WARNINGS
	)
else()
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

if(WIN32)
	set(PLATFORM_UI_SRC
		capture_if_details_dlg_win32.c
	)
endif()

register_tap_files(wireshark-tap-register.c
	taps
	${WIRESHARK_TAP_SRC}
)

if(WIN32)
	set(PORTAUDIO_OBJ $<TARGET_OBJECTS:portaudio>)
endif()

find_file(GLIB_COMPILE_RESOURCES
	glib-compile-resources${CMAKE_EXECUTABLE_SUFFIX}
	HINTS
		"${GLIB2_HINTS}/bin"
)

pkg_check_modules(GRESOURCE QUIET gio-2.0>=2.32 gdk-pixbuf-2.0>=2.26)

macro(WIRESHARK_GRESOURCES _outputfile _resourcefile)
	add_custom_command(
		OUTPUT ${_outputfile}
		COMMAND ${GLIB_COMPILE_RESOURCES} --sourcedir=${CMAKE_SOURCE_DIR} --target=${_outputfile} --generate --manual-register ${CMAKE_CURRENT_SOURCE_DIR}/${_resourcefile}
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${_resourcefile}
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	)
endmacro(WIRESHARK_GRESOURCES)

WIRESHARK_GRESOURCES(wireshark-gresources.h main.gresources.xml)

WIRESHARK_GRESOURCES(wireshark-gresources.c main.gresources.xml)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

if(GRESOURCE_FOUND AND NOT WIN32)
	set(PIXBUF_SRC
		wireshark-gresources.c
		wireshark-gresources.h
	)
	add_definitions(-DHAVE_GDK_GRESOURCE)
else()
	set(PIXBUF_SRC
		pixbuf-csource.c
	)
endif()

add_library(gtkui STATIC
	${WIRESHARK_GTK_SRC}
	${WIRESHARK_TAP_SRC}
	${PLATFORM_UI_SRC}
	${PORTAUDIO_OBJ}
	wireshark-tap-register.c
	${PIXBUF_SRC}
)
set_target_properties(gtkui PROPERTIES
	LINK_FLAGS "${WS_LINK_FLAGS}"
	FOLDER "UI")

CHECKAPI(
	NAME
	  gtk-base
	SWITCHES
	  -g deprecated-gtk
	SOURCES
	  ${WIRESHARK_GTK_SRC}
	  ${WIRESHARK_TAP_SRC}
	  ${PLATFORM_UI_SRC}
)
CHECKAPI(
	NAME
	  gtk-todo
	SWITCHES
	  -M -g deprecated-gtk-todo
	SOURCES
	  ${WIRESHARK_GTK_SRC}
	  ${WIRESHARK_TAP_SRC}
	  ${PLATFORM_UI_SRC}
)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
