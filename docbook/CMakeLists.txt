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
	wsdg_src/WSDG_chapter_build_intro.xml
	wsdg_src/WSDG_chapter_capture.xml
	wsdg_src/WSDG_chapter_dissection.xml
	wsdg_src/WSDG_chapter_env_intro.xml
	wsdg_src/WSDG_chapter_libraries.xml
	wsdg_src/WSDG_chapter_quick_setup.xml
	wsdg_src/WSDG_chapter_sources.xml
	wsdg_src/WSDG_chapter_tools.xml
	wsdg_src/WSDG_chapter_userinterface.xml
	wsdg_src/WSDG_chapter_works.xml
	wsdg_src/WSDG_meta_info.xml
	wsdg_src/WSDG_preface.xml
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
	svn_version.xml
	wsluarm
	${WSUG_FILES}
	${WSUG_GRAPHICS}
)

# developer-guide.xml must be first in the list
set(WSDG_SOURCE
	developer-guide.xml
	svn_version.xml
	${WSDG_FILES}
	${WSDG_GRAPHICS}
)

set(RELEASE_NOTES_SOURCE
	release-notes.xml
	svn_version.xml
)

set(WSLUA_MODULES
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_dumper.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_field.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_gui.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_listener.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_pinfo.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_proto.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_tree.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_tvb.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_util.c
)

find_package( FOP ) # Call before XSLTPROC
find_package( LYNX )
find_package( XSLTPROC )
find_package( XMLLINT )

ADD_CUSTOM_COMMAND(
	OUTPUT
		svn_version.xml
	COMMAND ${SH}
		${CMAKE_CURRENT_SOURCE_DIR}/check_svn_version.sh
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/check_svn_version.sh
)

add_custom_target(
	user_guides ALL
	DEPENDS
		wsluarm
		wsug_html_chunked/index.html
		wsug_html/user-guide.html
		user-guide-a4.pdf
		user-guide-us.pdf
)

VALIDATE_XML(
	wsug.validated
	WSUG_SOURCE
)

XML2HTML(
	wsug.validated
	wsug_html/user-guide.html
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
		wsdg_html/developer-guide.html
		developer-guide-a4.pdf
		developer-guide-us.pdf
)

VALIDATE_XML(
	wsdg.validated
	WSDG_SOURCE
)

XML2HTML(
	wsdg.validated
	wsdg_html/developer-guide.html
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

