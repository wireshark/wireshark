# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# To do:
# - Rename *.asciidoc to *.adoc
# - Make the build targets top-level on Windows, similar to the NSIS,
#   WiX, and PortableApps targets?

find_package( Asciidoctor 1.5 )
find_package( XSLTPROC )

function(set_docbook_target_properties _target)
	set_target_properties(${_target} PROPERTIES
		FOLDER "Docbook"
		EXCLUDE_FROM_DEFAULT_BUILD True
		)
endfunction(set_docbook_target_properties)

if(WIN32)
	find_package( HTMLHelp )
	if(HTML_HELP_COMPILER)
		# We do not need the HTML Help headers and library, just the
		# compiler. To avoid confusion, report the package as found.
		# https://gitlab.kitware.com/cmake/cmake/issues/15886
		set(HTMLHelp_FOUND 1)
	endif()
	macro( HHP2CHM _hhpsource )
		get_filename_component( _source_base_name ${_hhpsource} NAME_WE )

		add_custom_command(
			OUTPUT ${_output_chm}
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			# The number and order of arguments MUST match hhc.cmake.
			COMMAND ${CMAKE_COMMAND} -P
				${CMAKE_SOURCE_DIR}/cmake/modules/hhc.cmake
					"${HTML_HELP_COMPILER}"
					${_hhpsource}
			DEPENDS
				${_hhpsource}
		)
	endmacro()
else()
	macro( HHP2CHM _hhpsource )
	# Dummy.
	endmacro()
endif()

set(COMMON_FILES
	common_src/GPL_appendix.asciidoc
)

set(COMMON_GRAPHICS
	common_graphics/note.svg
	common_graphics/tip.svg
	common_graphics/warning.svg
)

set(WSUG_TOOLS_HELP_COMMANDS
	capinfos
	dumpcap
	editcap
	mergecap
	rawshark
	reordercap
	text2pcap
	tshark
)

# We want the wsug_* targets to depend on the tools help files.
# We want update_tools_help to be an independent target.
# We don't necessarily want to depend on building our executables before
# being able to build our documentation.
set(WSUG_TOOLS_HELP_FILES)
set(WSUG_TOOLS_PHONY_DEPS)
set(GUIDE_INSTALL_DIRS)

# General help output
foreach(th_command ${WSUG_TOOLS_HELP_COMMANDS})
	set(th_file ${CMAKE_CURRENT_SOURCE_DIR}/wsug_src/${th_command}-h.txt)
	set(th_phony ${th_command}_h_tools_help)
	list(APPEND WSUG_TOOLS_HELP_FILES ${th_file})
	list(APPEND WSUG_TOOLS_PHONY_DEPS ${th_phony})
	add_custom_command(
		OUTPUT ${th_phony}
		COMMAND ${th_command} -h > ${th_file}
		DEPENDS ${th_command}
	)
endforeach()

# Extra command output
# Note that these won't work on Windows unless we make -F and -T write
# to stdout and return 0 or wrap the commands similar to hhc.exe.
set(th_file ${CMAKE_CURRENT_SOURCE_DIR}/wsug_src/editcap-F.txt)
set(th_phony editcap_F_tools_help)
list(APPEND WSUG_TOOLS_HELP_FILES ${th_file})
list(APPEND WSUG_TOOLS_PHONY_DEPS ${th_phony})
add_custom_command(
	OUTPUT ${th_phony}
	COMMAND editcap -F > ${th_file}
	DEPENDS editcap
)
set(th_file ${CMAKE_CURRENT_SOURCE_DIR}/wsug_src/editcap-T.txt)
set(th_phony editcap_T_tools_help)
list(APPEND WSUG_TOOLS_HELP_FILES ${th_file})
list(APPEND WSUG_TOOLS_PHONY_DEPS ${th_phony})
add_custom_command(
	OUTPUT ${th_phony}
	COMMAND editcap -T > ${th_file}
	DEPENDS editcap
)

add_custom_target(update_tools_help
	DEPENDS ${WSUG_TOOLS_PHONY_DEPS}
)
set_docbook_target_properties(update_tools_help)

set(WSUG_FILES
	wsug_src/WSUG_app_files.asciidoc
	wsug_src/WSUG_app_howitworks.asciidoc
	wsug_src/WSUG_app_protocols.asciidoc
	wsug_src/WSUG_app_messages.asciidoc
	wsug_src/WSUG_app_tools.asciidoc
	wsug_src/WSUG_chapter_advanced.asciidoc
	wsug_src/WSUG_chapter_build_install.asciidoc
	wsug_src/WSUG_chapter_capture.asciidoc
	wsug_src/WSUG_chapter_customize.asciidoc
	wsug_src/WSUG_chapter_introduction.asciidoc
	wsug_src/WSUG_chapter_io.asciidoc
	wsug_src/WSUG_chapter_statistics.asciidoc
	wsug_src/WSUG_chapter_telephony.asciidoc
	wsug_src/WSUG_chapter_troubleshoot.asciidoc
	wsug_src/WSUG_chapter_use.asciidoc
	wsug_src/WSUG_chapter_work.asciidoc
	wsug_src/WSUG_preface.asciidoc
	${COMMON_FILES}
)

set(WSUG_GRAPHICS
	wsug_graphics/related-ack.png
	wsug_graphics/related-current.png
	wsug_graphics/related-dup-ack.png
	wsug_graphics/related-first.png
	wsug_graphics/related-last.png
	wsug_graphics/related-other.png
	wsug_graphics/related-request.png
	wsug_graphics/related-response.png
	wsug_graphics/related-segment.png
	wsug_graphics/ws-analyze-menu.png
	wsug_graphics/ws-bytes-pane-tabs.png
	wsug_graphics/ws-bytes-pane.png
	wsug_graphics/ws-capture-info.png
	wsug_graphics/ws-capture-interfaces.png
	wsug_graphics/ws-capture-interfaces-win32.png
	wsug_graphics/ws-capture-menu.png
	wsug_graphics/ws-capture-options.png
	wsug_graphics/ws-capture-options-remote-capture.png
	wsug_graphics/ws-capture-options-remote-interface.png
	wsug_graphics/ws-capture-options-remote-settings.png
	wsug_graphics/ws-capture-preferences.png
	wsug_graphics/ws-choose-color-rule.png
	wsug_graphics/ws-coloring-fields.png
	wsug_graphics/ws-coloring-rules-dialog.png
	wsug_graphics/ws-column-header-popup-menu.png
	wsug_graphics/ws-decode-as-show.png
	wsug_graphics/ws-decode-as.png
	wsug_graphics/ws-column-header-popup-menu.png
	wsug_graphics/ws-details-pane-popup-menu.png
	wsug_graphics/ws-details-pane.png
	wsug_graphics/ws-display-filter-tcp.png
	wsug_graphics/ws-edit-menu.png
	wsug_graphics/ws-enabled-protocols.png
	wsug_graphics/ws-expert-colored-tree.png
	wsug_graphics/ws-expert-column.png
	wsug_graphics/ws-expert-infos.png
	wsug_graphics/ws-export-objects.png
	wsug_graphics/ws-export-pdml.png
	wsug_graphics/ws-export-plain.png
	wsug_graphics/ws-export-ps.png
	wsug_graphics/ws-export-psml.png
	wsug_graphics/ws-export-selected.png
	wsug_graphics/ws-file-import.png
	wsug_graphics/ws-file-menu.png
	wsug_graphics/ws-file-set-dialog.png
	wsug_graphics/ws-filter-add-expression.png
	wsug_graphics/ws-filter-toolbar.png
	wsug_graphics/ws-filters.png
	wsug_graphics/ws-find-packet.png
	wsug_graphics/ws-follow-stream.png
	wsug_graphics/ws-go-menu.png
	wsug_graphics/ws-goto-packet.png
	wsug_graphics/ws-gui-colors-preferences.png
	wsug_graphics/ws-gui-columns-preferences.png
	wsug_graphics/ws-gui-config-profiles.png
	wsug_graphics/ws-gui-font-preferences.png
	wsug_graphics/ws-gui-layout-preferences.png
	wsug_graphics/ws-gui-preferences.png
	wsug_graphics/ws-help-menu.png
	wsug_graphics/ws-internals-menu.png
	wsug_graphics/ws-list-pane.png
	wsug_graphics/ws-logo.png
	wsug_graphics/ws-main-toolbar.png
	wsug_graphics/ws-main.png
	wsug_graphics/ws-menu.png
	wsug_graphics/ws-merge-gtk24.png
	wsug_graphics/ws-merge-win32.png
	wsug_graphics/ws-nameresolution-preferences.png
	wsug_graphics/ws-open-gtk24.png
	wsug_graphics/ws-open-win32.png
	wsug_graphics/ws-packet-format.png
	wsug_graphics/ws-packet-pane-popup-menu.png
	wsug_graphics/ws-packet-range.png
	wsug_graphics/ws-packet-selected.png
	wsug_graphics/ws-packet-sep-win.png
	wsug_graphics/ws-print.png
	wsug_graphics/ws-printing-preferences.png
	wsug_graphics/ws-save-as-gtk24.png
	wsug_graphics/ws-save-as-win32.png
	wsug_graphics/ws-statistics-menu.png
	wsug_graphics/ws-stats-conversations.png
	wsug_graphics/ws-stats-endpoints.png
	wsug_graphics/ws-stats-hierarchy.png
	wsug_graphics/ws-stats-iographs.png
	wsug_graphics/ws-stats-srt-dcerpc-filter.png
	wsug_graphics/ws-stats-srt-dcerpc.png
	wsug_graphics/ws-stats-summary.png
	wsug_graphics/ws-stats-lte-mac-traffic.png
	wsug_graphics/ws-stats-lte-rlc-traffic.png
	wsug_graphics/ws-stats-wlan-traffic.png
	wsug_graphics/ws-statusbar-empty.png
	wsug_graphics/ws-statusbar-loaded.png
	wsug_graphics/ws-statusbar-selected.png
	wsug_graphics/ws-telephony-menu.png
	wsug_graphics/ws-time-reference.png
	wsug_graphics/ws-tools-menu.png
	wsug_graphics/ws-view-menu.png
	wsug_graphics/toolbar/autoscroll_24.png
	wsug_graphics/toolbar/capture_filter_24.png
	wsug_graphics/toolbar/capture_interfaces_24.png
	wsug_graphics/toolbar/capture_options_24.png
	wsug_graphics/toolbar/capture_restart_24.png
	wsug_graphics/toolbar/capture_start_24.png
	wsug_graphics/toolbar/capture_stop_24.png
	wsug_graphics/toolbar/colorize_24.png
	wsug_graphics/toolbar/display_filter_24.png
	wsug_graphics/toolbar/resize_columns_24.png
	wsug_graphics/toolbar/stock_add_24.png
	wsug_graphics/toolbar/stock_apply_20.png
	wsug_graphics/toolbar/stock_bottom_24.png
	wsug_graphics/toolbar/stock_clear_24.png
	wsug_graphics/toolbar/stock_close_24.png
	wsug_graphics/toolbar/stock_colorselector_24.png
	wsug_graphics/toolbar/stock_help_24.png
	wsug_graphics/toolbar/stock_jump_to_24.png
	wsug_graphics/toolbar/stock_left_arrow_24.png
	wsug_graphics/toolbar/stock_open_24.png
	wsug_graphics/toolbar/stock_preferences_24.png
	wsug_graphics/toolbar/stock_print_24.png
	wsug_graphics/toolbar/stock_properties_24.png
	wsug_graphics/toolbar/stock_refresh_24.png
	wsug_graphics/toolbar/stock_right_arrow_24.png
	wsug_graphics/toolbar/stock_save_24.png
	wsug_graphics/toolbar/stock_save_as_24.png
	wsug_graphics/toolbar/stock_search_24.png
	wsug_graphics/toolbar/stock_stop_24.png
	wsug_graphics/toolbar/stock_top_24.png
	wsug_graphics/toolbar/stock_zoom_1_24.png
	wsug_graphics/toolbar/stock_zoom_in_24.png
	wsug_graphics/toolbar/stock_zoom_out_24.png
	${COMMON_GRAPHICS}
)

set(WSDG_FILES
	wsdg_src/WSDG_chapter_build_intro.asciidoc
	wsdg_src/WSDG_chapter_capture.asciidoc
	wsdg_src/WSDG_chapter_dissection.asciidoc
	wsdg_src/WSDG_chapter_env_intro.asciidoc
	wsdg_src/WSDG_chapter_libraries.asciidoc
	wsdg_src/WSDG_chapter_quick_setup.asciidoc
	wsdg_src/WSDG_chapter_sources.asciidoc
	wsdg_src/WSDG_chapter_tools.asciidoc
	wsdg_src/WSDG_chapter_userinterface.asciidoc
	wsdg_src/WSDG_chapter_works.asciidoc
	wsdg_src/WSDG_preface.asciidoc
	wsluarm.asciidoc
	${COMMON_FILES}
)

set(WSDG_GRAPHICS
	wsdg_graphics/ws-capture-sync.dia
	wsdg_graphics/ws-capture-sync.png
	wsdg_graphics/ws-capture_internals.dia
	wsdg_graphics/ws-capture_internals.png
	wsdg_graphics/ws-function-blocks.dia
	wsdg_graphics/ws-function-blocks.png
	wsdg_graphics/ws-logo.png
	${COMMON_GRAPHICS}
)

set(WSUG_SOURCE
	${WSUG_FILES}
	${WSUG_GRAPHICS}
)

if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	add_custom_command(
		OUTPUT ws.css
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			${CMAKE_CURRENT_SOURCE_DIR}/ws.css
			${CMAKE_CURRENT_BINARY_DIR}/ws.css
		DEPENDS
			${CMAKE_CURRENT_SOURCE_DIR}/ws.css
	)
endif()

set( WSUG_BUILT_DEPS ws.css ${WSUG_TOOLS_HELP_FILES})

set(WSDG_SOURCE
	${WSDG_FILES}
	${WSDG_GRAPHICS}
)

# Note: file order here MATTERS!
# new WSLUA_MODULE files must come right before any WSLUA_CONTINUE_MODULE
# files for the same module
set(WSLUA_MODULES
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_dumper.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_field.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_gui.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_int64.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_listener.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_pinfo.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_address.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_column.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_nstime.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_proto.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_dissector.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_pref.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_proto_expert.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_proto_field.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_tree.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_tvb.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_byte_array.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_file.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_file_handler.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_frame_info.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_capture_info.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_dir.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_util.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_struct.c
)

# Empty file to trigger wsluarm generation.
ADD_CUSTOM_COMMAND(
	OUTPUT
		wsluarm
	COMMAND ${CMAKE_COMMAND} -E make_directory wsluarm_src
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_CURRENT_SOURCE_DIR}/make-wsluarm.pl
		${WSLUA_MODULES}
	COMMAND ${CMAKE_COMMAND} -E touch
		wsluarm
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/make-wsluarm.pl
		${WSLUA_MODULES}
)

set( WSDG_BUILT_DEPS ws.css wsluarm )

set( ASCIIDOC_CONF_FILES
	attributes.asciidoc
	# XXX Add macros
)

if(ASCIIDOCTOR_EXECUTABLE)
	# Generate the DocBook sources of user and developer guides

	ASCIIDOCTOR2DOCBOOK(user-guide.asciidoc ${ASCIIDOC_CONF_FILES} ${WSUG_SOURCE} ${WSUG_BUILT_DEPS})
	add_custom_target(user_guide_docbook DEPENDS generate_user-guide.xml)
	set_docbook_target_properties(user_guide_docbook)

	ASCIIDOCTOR2DOCBOOK(developer-guide.asciidoc ${ASCIIDOC_CONF_FILES} ${WSDG_SOURCE} ${WSDG_BUILT_DEPS})
	add_custom_target(developer_guide_docbook DEPENDS generate_developer-guide.xml)
	set_docbook_target_properties(developer_guide_docbook)

	# Top-level guide targets.

	add_custom_target(user_guides DEPENDS user_guide_docbook)
	set_docbook_target_properties(user_guides)

	add_custom_target(developer_guides DEPENDS developer_guide_docbook)
	set_docbook_target_properties(developer_guides)

	add_custom_target(all_guides DEPENDS user_guides developer_guides )
	set_docbook_target_properties(all_guides)
endif()

# User's Guide chain.
if(ASCIIDOCTOR_EXECUTABLE AND XSLTPROC_EXECUTABLE)
	XML2HTML(
		user_guide
		wsug
		single-page
		user-guide.xml
		WSUG_GRAPHICS
	)

	XML2HTML(
		user_guide
		wsug
		chunked
		user-guide.xml
		WSUG_GRAPHICS
	)
	add_custom_target(
		user_guide_html
		DEPENDS
			wsug_html/index.html
			wsug_html_chunked/index.html
	)
	set_docbook_target_properties(user_guide_html)
	add_dependencies(user_guides user_guide_html)
	list(APPEND GUIDE_INSTALL_DIRS ${CMAKE_CURRENT_BINARY_DIR}/wsug_html_chunked)
endif()

if(ASCIIDOCTOR_EXECUTABLE)
	ASCIIDOCTOR2PDF(user-guide.asciidoc ${WSUG_SOURCE} ${WSUG_BUILT_DEPS})

	add_custom_target(
		user_guide_pdf
		DEPENDS
			user-guide.pdf
	)
	set_docbook_target_properties(user_guide_pdf)
	add_dependencies(user_guides user_guide_pdf)
endif()

if(WIN32 AND ASCIIDOCTOR_EXECUTABLE)
	XML2HHP(user_guide wsug user-guide.xml)
	HHP2CHM(user-guide.hhp)
	add_custom_target(
		user_guide_chm
		DEPENDS
			user-guide.chm
	)
	set_docbook_target_properties(user_guide_chm)
	add_dependencies(user_guides user_guide_chm)
endif()

# Developer's Guide chain.
if(ASCIIDOCTOR_EXECUTABLE AND XSLTPROC_EXECUTABLE)
	XML2HTML(
		developer_guide
		wsdg
		single-page
		developer-guide.xml
		WSDG_GRAPHICS
	)

	XML2HTML(
		developer_guide
		wsdg
		chunked
		developer-guide.xml
		WSDG_GRAPHICS
	)
	add_custom_target(
		developer_guide_html
		DEPENDS
			wsdg_html/index.html
			wsdg_html_chunked/index.html
	)
	set_docbook_target_properties(developer_guide_html)
	add_dependencies(developer_guides developer_guide_html)
	list(APPEND GUIDE_INSTALL_DIRS ${CMAKE_CURRENT_BINARY_DIR}/wsdg_html_chunked)
endif()

if(ASCIIDOCTOR_EXECUTABLE)
	ASCIIDOCTOR2PDF(developer-guide.asciidoc ${WSDG_SOURCE} ${WSDG_BUILT_DEPS})

	add_custom_target(
		developer_guide_pdf
		DEPENDS
			developer-guide.pdf
	)
	set_docbook_target_properties(developer_guide_pdf)
	add_dependencies(developer_guides developer_guide_pdf)
endif()

if(WIN32 AND ASCIIDOCTOR_EXECUTABLE)
	XML2HHP(developer_guide	wsdg developer-guide.xml)
	HHP2CHM(developer-guide.hhp)
	add_custom_target(
		developer_guide_chm
		DEPENDS
			developer-guide.chm
	)
	set_docbook_target_properties(developer_guide_chm)
	add_dependencies(developer_guides developer_guide_chm)
endif()

if (GUIDE_INSTALL_DIRS)
	# The installation location and DOC_DIR in ui/help_url.c must
	# match.
	add_custom_target(install_guides
		COMMAND ${CMAKE_COMMAND} -P
			${CMAKE_SOURCE_DIR}/cmake/modules/FileInstall.cmake
			${GUIDE_INSTALL_DIRS}
			${CMAKE_INSTALL_FULL_DOCDIR}
		DEPENDS
			user_guide_html developer_guide_html
	)
	set_docbook_target_properties(install_guides)
endif()

# release_notes: release-notes.html release-notes.txt

add_custom_target( release_notes_html DEPENDS release-notes.html )
set_docbook_target_properties(release_notes_html)
add_custom_target( release_notes_txt DEPENDS release-notes.txt )
set_docbook_target_properties(release_notes_txt)

# Force serial execution so that separate asciidoctor instances don't
# trip on each other
# add_dependencies ( release_notes_txt release_notes_html )

add_custom_target( release_notes )
set_docbook_target_properties(release_notes)
add_dependencies ( release_notes release_notes_txt release_notes_html )

add_custom_target(
	news
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${CMAKE_CURRENT_BINARY_DIR}/release-notes.txt
		${CMAKE_SOURCE_DIR}/NEWS
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/release-notes.txt
)
set_docbook_target_properties(news)

if( ASCIIDOCTOR_FOUND )
	ASCIIDOCTOR2HTML( release-notes.asciidoc ws.css )
	ASCIIDOCTOR2TXT( release-notes.asciidoc )
endif()

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
