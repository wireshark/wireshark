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

find_package( LYNX )
find_package( XSLTPROC )
if(ENABLE_CHM_GUIDES)
	find_package( HTMLHelp )
endif()

find_package( ASCIIDOC )

if(WIN32)
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

set(COMMON_GRAPHICS
	common_graphics/note.svg
	common_graphics/tip.svg
	common_graphics/warning.svg
)

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

set( WSUG_BUILT_DEPS ws.css )

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

if(ENABLE_HTML_GUIDES OR ENABLE_PDF_GUIDES OR ENABLE_CHM_GUIDES)
	# Generate the DocBook sources of user and developer guides

	set( ASCIIDOC_CONF_FILES asciidoc.conf asciidoctor-asciidoc.conf )

	ASCIIDOC2DOCBOOK(user-guide.asciidoc ASCIIDOC_CONF_FILES WSUG_SOURCE WSUG_BUILT_DEPS)
	add_custom_target(user_guide_docbook DEPENDS generate_user-guide.xml)
	set_target_properties(user_guide_docbook PROPERTIES FOLDER "Docbook")

	ASCIIDOC2DOCBOOK(developer-guide.asciidoc ASCIIDOC_WSLUARM_CONF_FILES WSDG_SOURCE WSDG_BUILT_DEPS)
	add_custom_target(developer_guide_docbook DEPENDS generate_developer-guide.xml)
	set_target_properties(developer_guide_docbook PROPERTIES FOLDER "Docbook")

	# Top-level guide targets.

	add_custom_target(user_guides DEPENDS user_guide_docbook)
	set_target_properties(user_guides PROPERTIES FOLDER "Docbook")

	add_custom_target(developer_guides DEPENDS developer_guide_docbook)
	set_target_properties(developer_guides PROPERTIES FOLDER "Docbook")

	add_custom_target(all_guides ALL DEPENDS user_guides developer_guides )
	set_target_properties(all_guides PROPERTIES FOLDER "Docbook")
endif()

# User's Guide chain.
if(ENABLE_HTML_GUIDES)
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
	set_target_properties(user_guide_html PROPERTIES FOLDER "Docbook")
	add_dependencies(user_guides user_guide_html)
endif()

if(ENABLE_PDF_GUIDES)
	# To do:
	# - Merge A4 and letter into the smallest dimension of each format.
	#   Use   --stringparam  page.height <letter-height>mm --stringparam  page.width <at-width>mm
	#   Test the effect of this on letter and a4 printers first (ps and non-ps).
	# - Generate PDFs using AsciiDoc.

	XML2PDF(
		user_guide
		user-guide-a4.pdf
		user-guide.xml
		custom_layer_pdf.xsl
		A4
	)

	XML2PDF(
		user_guide
		user-guide-us.pdf
		user-guide.xml
		custom_layer_pdf.xsl
		letter
	)
	add_custom_target(
		user_guide_pdf_a4
		DEPENDS
			user-guide-a4.pdf
	)
	set_target_properties(user_guide_pdf_a4 PROPERTIES FOLDER "Docbook")
	add_custom_target(
		user_guide_pdf_us
		DEPENDS
			user-guide-us.pdf
	)
	set_target_properties(user_guide_pdf_us PROPERTIES FOLDER "Docbook")
	add_dependencies(user_guides user_guide_pdf_a4 user_guide_pdf_us)
endif()

if(ENABLE_CHM_GUIDES)
	XML2HHP(user_guide wsug user-guide.xml)
	HHP2CHM(user-guide.hhp)
	add_custom_target(
		user_guide_chm
		DEPENDS
			user-guide.chm
	)
	set_target_properties(user_guide_chm PROPERTIES FOLDER "Docbook")
	add_dependencies(user_guides user_guide_chm)
endif()

# Developer's Guide chain.
if(ENABLE_HTML_GUIDES)
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
	set_target_properties(developer_guide_html PROPERTIES FOLDER "Docbook")
	add_dependencies(developer_guides developer_guide_html)
endif()

if(ENABLE_PDF_GUIDES)
	XML2PDF(
		developer_guide
		developer-guide-a4.pdf
		developer-guide.xml
		custom_layer_pdf.xsl
		A4
	)

	XML2PDF(
		developer_guide
		developer-guide-us.pdf
		developer-guide.xml
		custom_layer_pdf.xsl
		letter
	)
	add_custom_target(
		developer_guide_pdf_a4
		DEPENDS
			developer-guide-a4.pdf
	)
	set_target_properties(developer_guide_pdf_a4 PROPERTIES FOLDER "Docbook")
	add_custom_target(
		developer_guide_pdf_us
		DEPENDS
			developer-guide-us.pdf
	)
	set_target_properties(developer_guide_pdf_us PROPERTIES FOLDER "Docbook")
	add_dependencies(developer_guides developer_guide_pdf_a4 developer_guide_pdf_us)
endif()

if(ENABLE_CHM_GUIDES)
	XML2HHP(developer_guide	wsdg developer-guide.xml)
	HHP2CHM(developer-guide.hhp)
	add_custom_target(
		developer_guide_chm
		DEPENDS
			developer-guide.chm
	)
	set_target_properties(developer_guide_chm PROPERTIES FOLDER "Docbook")
	add_dependencies(developer_guides developer_guide_chm)
endif()

# release_notes: release-notes.html release-notes.txt release-notes-a4.pdf release-notes-us.pdf

add_custom_target( release_notes_html DEPENDS ws.css release-notes.html )
set_target_properties(release_notes_html PROPERTIES FOLDER "Docbook")
add_custom_target( release_notes_txt DEPENDS release-notes.txt )
set_target_properties(release_notes_txt PROPERTIES FOLDER "Docbook")

# Force serial execution so that separate a2x instances don't trip on each other
add_dependencies ( release_notes_txt release_notes_html )

add_custom_target( release_notes )
set_target_properties(release_notes PROPERTIES FOLDER "Docbook")
add_dependencies ( release_notes release_notes_txt release_notes_html )

add_custom_target(
	news
	COMMAND ${CMAKE_COMMAND} -E copy_if_different
		${CMAKE_CURRENT_BINARY_DIR}/release-notes.txt
		${CMAKE_SOURCE_DIR}/NEWS
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/release-notes.txt
)
set_target_properties(news PROPERTIES FOLDER "Docbook")

ASCIIDOC2HTML(
	release-notes.html
	release-notes.asciidoc
	"${ASCIIDOC_CONF_FILES}"
)

ASCIIDOC2TXT(
	release-notes.txt
	release-notes.asciidoc
	"${ASCIIDOC_CONF_FILES}"
)

#ASCIIDOC2PDF(
#	release-notes-a4.pdf
#	release-notes.asciidoc
#	"${ASCIIDOC_CONF_FILES}"
#	A4
#)

#ASCIIDOC2PDF(
#	release-notes-us.pdf
#	release-notes.asciidoc
#	"${ASCIIDOC_CONF_FILES}"
#	letter
#)
