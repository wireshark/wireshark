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

find_package( FOP ) # Call before XSLTPROC
find_package( LYNX )
find_package( XSLTPROC )
find_package( XMLLINT )
find_package( ASCIIDOC )

set(WSUG_FILES
	wsug_src/WSUG_app_files.xml
	wsug_src/WSUG_app_howitworks.xml
	wsug_src/WSUG_app_messages.xml
	wsug_src/WSUG_app_protocols.xml
	wsug_src/WSUG_app_tools.xml
	wsug_src/WSUG_chapter_advanced.xml
	wsug_src/WSUG_chapter_build_install.xml
	wsug_src/WSUG_chapter_capture.xml
	wsug_src/WSUG_chapter_customize.xml
	wsug_src/WSUG_chapter_introduction.xml
	wsug_src/WSUG_chapter_io.xml
	wsug_src/WSUG_chapter_statistics.xml
	wsug_src/WSUG_chapter_telephony.xml
	wsug_src/WSUG_chapter_troubleshoot.xml
	wsug_src/WSUG_chapter_use.xml
	wsug_src/WSUG_chapter_work.xml
	wsug_src/WSUG_meta_info.xml
	wsug_src/WSUG_preface.xml
	wsluarm.xml
	ws.css
)

set(WSUG_GRAPHICS
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
	wsug_graphics/ws-edit-color-rule-dialog.png
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
	wsug_graphics/ws-merge-gtk20.png
	wsug_graphics/ws-merge-gtk24.png
	wsug_graphics/ws-merge-win32.png
	wsug_graphics/ws-nameresolution-preferences.png
	wsug_graphics/ws-open-gtk20.png
	wsug_graphics/ws-open-gtk24.png
	wsug_graphics/ws-open-win32.png
	wsug_graphics/ws-packet-format.png
	wsug_graphics/ws-packet-pane-popup-menu.png
	wsug_graphics/ws-packet-range.png
	wsug_graphics/ws-packet-selected.png
	wsug_graphics/ws-packet-sep-win.png
	wsug_graphics/ws-print.png
	wsug_graphics/ws-printing-preferences.png
	wsug_graphics/ws-save-as-gtk20.png
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
	wsug_graphics/note.png
	wsug_graphics/tip.png
	wsug_graphics/warning.png
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
	ws.css
)

set(WSDG_GRAPHICS
	wsdg_graphics/ws-capture-sync.dia
	wsdg_graphics/ws-capture-sync.png
	wsdg_graphics/ws-capture_internals.dia
	wsdg_graphics/ws-capture_internals.png
	wsdg_graphics/ws-function-blocks.dia
	wsdg_graphics/ws-function-blocks.png
	wsdg_graphics/ws-logo.png
	wsdg_graphics/note.png
	wsdg_graphics/tip.png
	wsdg_graphics/warning.png
)

# user-guide.xml must be first in the list
set(WSUG_SOURCE
	user-guide.xml
	git_version.xml
	wsluarm
	${WSUG_FILES}
	${WSUG_GRAPHICS}
)

MACRO( ASCIIDOC2DOCBOOK _asciidocsource _conffile )
	GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
	set( A2X_HTML_OPTS --stylesheet=ws.css )
	set( _output_xml ${_source_base_name}.xml )
	set( _output_dbk ${_source_base_name}.dbk )
	ADD_CUSTOM_COMMAND(
		OUTPUT
			${_output_xml}
		# XXX - Output to a specific directory, e.g. wsdg_generated_src
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMAND ${A2X_EXECUTABLE}
			--verbose
			--attribute=docinfo
			--destination-dir=${CMAKE_CURRENT_BINARY_DIR}
			--asciidoc-opts="--conf-file=${CMAKE_CURRENT_SOURCE_DIR}/${_conffile}"
			--no-xmllint
			--format=docbook
			--fop
			${A2X_HTML_OPTS}
			${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
		DEPENDS
			${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
			${CMAKE_CURRENT_SOURCE_DIR}/${_conffile}
			${WSDG_GENERATED_FILES}
	)
ENDMACRO()

ASCIIDOC2DOCBOOK( developer-guide.asciidoc asciidoc.conf )

SET( WSDG_GENERATED_FILES )
# Convert an AsciiDoc document to a DocBook chapter
# Used for chapter-by-chapter conversion from DocBook to AsciiDoc.
# Can be removed after the User's Guide is converted.
# .asciidoc -> whole book (.dbk) -> chapter (.xml)
MACRO( ASCIIDOC2CHAPTER _asciidocsource _conffile )
	GET_FILENAME_COMPONENT( _source_base_name ${_asciidocsource} NAME_WE )
	set( A2X_HTML_OPTS --stylesheet=ws.css )
	set( _output_xml ${_source_base_name}.xml )
	set( _output_dbk ${_source_base_name}.dbk )
	ADD_CUSTOM_COMMAND(
		OUTPUT
			${_output_xml} ${_output_dbk}
		# XXX - Output to a specific directory, e.g. wsdg_generated_src
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMAND ${A2X_EXECUTABLE}
			--verbose
			--destination-dir=${CMAKE_CURRENT_BINARY_DIR}
			--asciidoc-opts="--conf-file=${CMAKE_CURRENT_SOURCE_DIR}/${_conffile}"
			--no-xmllint
			--fop
			--format=docbook --doctype=book
			${A2X_HTML_OPTS}
			${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
		COMMAND mv
			${_output_xml}
			${_output_dbk}
		COMMAND ${XMLLINT_EXECUTABLE}
			--xpath '//chapter | //preface'
			${_output_dbk}
			> ${_output_xml}
		DEPENDS
			${_outptudir}
	${CMAKE_CURRENT_SOURCE_DIR}/${_asciidocsource}
	${CMAKE_CURRENT_SOURCE_DIR}/${_conffile}
	)
	LIST( APPEND WSDG_GENERATED_FILES ${CMAKE_CURRENT_BINARY_DIR}/${_output_xml} )
ENDMACRO()

#FOREACH(ASCIIDOCFILE ${WSDG_ASCIIDOC_FILES})
#	ASCIIDOC2CHAPTER(
#		${ASCIIDOCFILE}
#		asciidoc.conf
#	)
#ENDFOREACH()

#ADD_CUSTOM_TARGET( wsdg_generated_src DEPENDS ${WSDG_GENERATED_FILES} )

# developer-guide.xml must be first in the list
set(WSDG_SOURCE
	developer-guide.xml
	git_version.xml
	${WSDG_FILES}
	${WSDG_GRAPHICS}
)

set(WSLUA_MODULES
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_dumper.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_field.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_gui.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_int64.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_listener.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_pinfo.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_proto.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_tree.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_tvb.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_file.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_dir.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_util.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_struct.c
)

ADD_CUSTOM_COMMAND(
	OUTPUT
		git_version.xml
	COMMAND ${SH}
		${CMAKE_CURRENT_SOURCE_DIR}/check_git_version.sh
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/check_git_version.sh
)

add_custom_target(
	user_guides ALL
	DEPENDS
		wsluarm
		wsug_html_chunked/index.html
		wsug_html/index.html
		user-guide-a4.pdf
		user-guide-us.pdf
)

VALIDATE_XML(
	wsug.validated
	WSUG_SOURCE
)

XML2HTML(
	wsug.validated
	wsug_html/index.html
	single-page
	WSUG_SOURCE
	WSUG_GRAPHICS
)

XML2HTML(
	wsug.validated
	wsug_html_chunked/index.html
	chunked
	WSUG_SOURCE
	WSUG_GRAPHICS
)

# 2do: Merge A4 and letter into the smallest dimension of each format.
#      Use   --stringparam  page.height <letter-height>mm --stringparam  page.width <at-width>mm
#      Test the effect of this on letter and a4 printers first (ps and non-ps).

XML2PDF(
	user-guide-a4.pdf
	WSUG_SOURCE
	custom_layer_pdf.xsl
	A4
)

XML2PDF(
	user-guide-us.pdf
	WSUG_SOURCE
	custom_layer_pdf.xsl
	letter
)

add_custom_target(
	developer_guides ALL
	DEPENDS
		wsluarm
		wsdg_html_chunked/index.html
		wsdg_html/index.html
		developer-guide-a4.pdf
		developer-guide-us.pdf
)

VALIDATE_XML(
	wsdg.validated
	WSDG_SOURCE
)

XML2HTML(
	wsdg.validated
	wsdg_html/index.html
	single-page
	WSDG_SOURCE
	WSDG_GRAPHICS
)

XML2HTML(
	wsdg.validated
	wsdg_html_chunked/index.html
	chunked
	WSDG_SOURCE
	WSDG_GRAPHICS
)

XML2PDF(
	developer-guide-a4.pdf
	WSDG_SOURCE
	custom_layer_pdf.xsl
	A4
)

XML2PDF(
	developer-guide-us.pdf
	WSDG_SOURCE
	custom_layer_pdf.xsl
	letter
)

# release_notes: release-notes.html release-notes.txt release-notes-a4.pdf release-notes-us.pdf

add_custom_target(
	release_notes ALL
	DEPENDS
		release-notes.html
		release-notes.txt
		release-notes-a4.pdf
		release-notes-us.pdf
		${CMAKE_SOURCE_DIR}/NEWS
)

ADD_CUSTOM_COMMAND(
	OUTPUT
		${CMAKE_SOURCE_DIR}/NEWS
	COMMAND cp
		${CMAKE_CURRENT_BINARY_DIR}/release-notes.txt
		${CMAKE_SOURCE_DIR}/NEWS
	DEPENDS
                ${CMAKE_CURRENT_BINARY_DIR}/release-notes.txt
)

ASCIIDOC2HTML(
	release-notes.html
	release-notes.asciidoc
	asciidoc.conf
)

ASCIIDOC2TXT(
	release-notes.txt
	release-notes.asciidoc
	asciidoc.conf
)

ASCIIDOC2PDF(
	release-notes-a4.pdf
	release-notes.asciidoc
	asciidoc.conf
	A4
)

ASCIIDOC2PDF(
	release-notes-us.pdf
	release-notes.asciidoc
	asciidoc.conf
	letter
)

# wsluarm
ADD_CUSTOM_COMMAND(
	OUTPUT
		wsluarm
	COMMAND cmake -E make_directory wsluarm_src
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_CURRENT_SOURCE_DIR}/make-wsluarm.pl
		${WSLUA_MODULES}
	COMMAND
		touch wsluarm
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/make-wsluarm.pl
		${WSLUA_MODULES}
)

