# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# To do:
# - Make the build targets top-level on Windows, similar to the NSIS,
#   WiX, and PortableApps targets?

function(set_docbook_target_properties _target)
	set_target_properties(${_target} PROPERTIES
		FOLDER "Documentation"
		EXCLUDE_FROM_DEFAULT_BUILD True
		)
endfunction(set_docbook_target_properties)

set(COMMON_FILES
	common_src/gpl_appendix.adoc
	common_src/typographic_conventions.adoc
)

set(WSUG_TITLE "Wireshark User's Guide")

set(WSUG_FILES
	wsug_src/wsug_advanced.adoc
	wsug_src/wsug_build_install.adoc
	wsug_src/wsug_capture.adoc
	wsug_src/wsug_customize.adoc
	wsug_src/wsug_files.adoc
	wsug_src/wsug_howitworks.adoc
	wsug_src/wsug_introduction.adoc
	wsug_src/wsug_io.adoc
	wsug_src/wsug_mate.adoc
	wsug_src/wsug_messages.adoc
	wsug_src/wsug_preface.adoc
	wsug_src/wsug_protocols.adoc
	wsug_src/wsug_statistics.adoc
	wsug_src/wsug_telephony.adoc
	wsug_src/wsug_tools.adoc
	wsug_src/wsug_troubleshoot.adoc
	wsug_src/wsug_use.adoc
	wsug_src/wsug_work.adoc
	wsug_src/capinfos-h.txt
	wsug_src/dumpcap-h.txt
	wsug_src/editcap-F.txt
	wsug_src/editcap-T.txt
	wsug_src/editcap-h.txt
	wsug_src/mergecap-h.txt
	wsug_src/rawshark-h.txt
	wsug_src/reordercap-h.txt
	wsug_src/text2pcap-h.txt
	wsug_src/tshark-h.txt
	wsug_src/wireshark-h.txt
	${COMMON_FILES}
)

# Note: Images should be minimized using tools/compress-pngs.py.
set(WSUG_GRAPHICS
	wsug_src/images/caution.svg
	wsug_src/images/important.svg
	wsug_src/images/note.svg
	wsug_src/images/related-ack.png
	wsug_src/images/related-current.png
	wsug_src/images/related-dup-ack.png
	wsug_src/images/related-first.png
	wsug_src/images/related-last.png
	wsug_src/images/related-other.png
	wsug_src/images/related-request.png
	wsug_src/images/related-response.png
	wsug_src/images/related-segment.png
	wsug_src/images/tip.svg
	wsug_src/images/toolbar/document-open.png
	wsug_src/images/toolbar/edit-find.png
	wsug_src/images/toolbar/filter-toolbar-add.png
	wsug_src/images/toolbar/filter-toolbar-apply.png
	wsug_src/images/toolbar/filter-toolbar-bookmark.png
	wsug_src/images/toolbar/filter-toolbar-clear.png
	wsug_src/images/toolbar/filter-toolbar-input.png
	wsug_src/images/toolbar/filter-toolbar-recent.png
	wsug_src/images/toolbar/go-first.png
	wsug_src/images/toolbar/go-jump.png
	wsug_src/images/toolbar/go-last.png
	wsug_src/images/toolbar/go-next.png
	wsug_src/images/toolbar/go-previous.png
	wsug_src/images/toolbar/x-capture-file-close.png
	wsug_src/images/toolbar/x-capture-file-reload.png
	wsug_src/images/toolbar/x-capture-file-save.png
	wsug_src/images/toolbar/x-capture-options.png
	wsug_src/images/toolbar/x-capture-restart.png
	wsug_src/images/toolbar/x-capture-start.png
	wsug_src/images/toolbar/x-capture-stop.png
	wsug_src/images/toolbar/x-colorize-packets.png
	wsug_src/images/toolbar/x-resize-columns.png
	wsug_src/images/toolbar/x-stay-last.png
	wsug_src/images/toolbar/zoom-in.png
	wsug_src/images/toolbar/zoom-original.png
	wsug_src/images/toolbar/zoom-out.png
	wsug_src/images/warning.svg
	wsug_src/images/ws-about-codecs.png
	wsug_src/images/ws-analyze-menu.png
	wsug_src/images/ws-bytes-pane-popup-menu.png
	wsug_src/images/ws-bytes-pane-tabs.png
	wsug_src/images/ws-bytes-pane.png
	wsug_src/images/ws-capture-file-properties.png
	wsug_src/images/ws-capture-info.png
	wsug_src/images/ws-capture-interfaces-main-macos.png
	wsug_src/images/ws-capture-interfaces-main-win32.png
	wsug_src/images/ws-capture-menu.png
	wsug_src/images/ws-capture-options-compile-selected-bpfs.png
	wsug_src/images/ws-capture-options-options.png
	wsug_src/images/ws-capture-options-output.png
	wsug_src/images/ws-capture-options-output.png
	wsug_src/images/ws-capture-options.png
	wsug_src/images/ws-choose-color-rule.png
	wsug_src/images/ws-coloring-fields.png
	wsug_src/images/ws-coloring-rules-dialog.png
	wsug_src/images/ws-column-header-popup-menu.png
	wsug_src/images/ws-decode-as.png
	wsug_src/images/ws-details-pane-popup-menu.png
	wsug_src/images/ws-details-pane.png
	wsug_src/images/ws-diagram-pane-popup-menu.png
	wsug_src/images/ws-diagram-pane.png
	wsug_src/images/ws-display-filter-tcp.png # GTK+
	wsug_src/images/ws-edit-menu.png
	wsug_src/images/ws-enabled-protocols.png
	wsug_src/images/ws-expert-colored-tree.png
	wsug_src/images/ws-expert-column.png
	wsug_src/images/ws-expert-information.png
	wsug_src/images/ws-export-objects.png
	wsug_src/images/ws-export-packet-dissections.png
	wsug_src/images/ws-export-selected.png
	wsug_src/images/ws-export-specified-packets.png
	wsug_src/images/ws-file-import.png
	wsug_src/images/ws-file-menu.png
	wsug_src/images/ws-file-set-dialog.png # GTK+
	wsug_src/images/ws-filter-add-expression.png # GTK+
	wsug_src/images/ws-filter-toolbar.png
	wsug_src/images/ws-filters.png # GTK+
	wsug_src/images/ws-find-packet.png
	wsug_src/images/ws-follow-http2-stream.png
	wsug_src/images/ws-follow-sip-stream.png
	wsug_src/images/ws-follow-stream.png
	wsug_src/images/ws-go-menu.png
	wsug_src/images/ws-goto-packet.png
	wsug_src/images/ws-help-menu.png
	wsug_src/images/ws-list-pane.png # Outdated
	wsug_src/images/ws-main-toolbar.png
	wsug_src/images/ws-main.png
	wsug_src/images/ws-manage-interfaces.png
	wsug_src/images/ws-mate-analysis.png
	wsug_src/images/ws-mate-dns_pane.png
	wsug_src/images/ws-mate-dns_pdu.png
	wsug_src/images/ws-mate-ftp_over_gre.png
	wsug_src/images/ws-mate-gop_analysis.png
	wsug_src/images/ws-mate-isup_over_mtp3_over_ip.png
	wsug_src/images/ws-mate-mmse_over_http.png
	wsug_src/images/ws-mate-pdu_analysis.png
	wsug_src/images/ws-mate-tcp-output.png
	wsug_src/images/ws-mate-transform.png
	wsug_src/images/ws-menu.png
	wsug_src/images/ws-merge-qt5.png
	wsug_src/images/ws-merge-win32.png
	wsug_src/images/ws-open-qt5.png
	wsug_src/images/ws-open-win32.png
	wsug_src/images/ws-packet-format.png
	wsug_src/images/ws-packet-pane-popup-menu.png
	wsug_src/images/ws-packet-range.png
	wsug_src/images/ws-packet-selected.png
	wsug_src/images/ws-packet-sep-win.png
	wsug_src/images/ws-pref-advanced.png
	wsug_src/images/ws-pref-appearance-columns.png
	wsug_src/images/ws-pref-appearance-fonts-and-colors.png
	wsug_src/images/ws-pref-appearance-layout.png
	wsug_src/images/ws-pref-appearance.png
	wsug_src/images/ws-pref-capture.png
	wsug_src/images/ws-pref-expert.png
	wsug_src/images/ws-pref-filter-buttons.png
	wsug_src/images/ws-pref-name-resolution.png
	wsug_src/images/ws-pref-protocols.png
	wsug_src/images/ws-pref-rsa-keys.png
	wsug_src/images/ws-pref-statistics.png
	wsug_src/images/ws-print.png
	wsug_src/images/ws-save-as-qt5.png
	wsug_src/images/ws-save-as-win32.png
	wsug_src/images/ws-statistics-menu.png
	wsug_src/images/ws-stats-conversations.png
	wsug_src/images/ws-stats-endpoints.png
	wsug_src/images/ws-stats-hierarchy.png
	wsug_src/images/ws-stats-iographs.png
	wsug_src/images/ws-stats-lte-mac-traffic.png
	wsug_src/images/ws-stats-lte-rlc-traffic.png
	wsug_src/images/ws-stats-packet-lengths.png
	wsug_src/images/ws-stats-srt-smb2.png
	wsug_src/images/ws-stats-wlan-traffic.png # GTK+
	wsug_src/images/ws-statusbar-empty.png
	wsug_src/images/ws-statusbar-filter.png
	wsug_src/images/ws-statusbar-loaded.png
	wsug_src/images/ws-statusbar-profile.png
	wsug_src/images/ws-statusbar-selected.png
	wsug_src/images/ws-tcp-analysis.png
	wsug_src/images/ws-tel-playlist.png
	wsug_src/images/ws-tel-rtp-player_1.png
	wsug_src/images/ws-tel-rtp-player_2.png
	wsug_src/images/ws-tel-rtp-player_3.png
	wsug_src/images/ws-tel-rtp-player_button.png
	wsug_src/images/ws-tel-rtp-streams.png
	wsug_src/images/ws-tel-rtpstream-analysis_1.png
	wsug_src/images/ws-tel-rtpstream-analysis_2.png
	wsug_src/images/ws-tel-rtpstream-analysis_3.png
	wsug_src/images/ws-tel-seq-dialog.png
	wsug_src/images/ws-tel-voip-calls.png
	wsug_src/images/ws-telephony-menu.png
	wsug_src/images/ws-time-reference.png # GTK+
	wsug_src/images/ws-tools-menu.png
	wsug_src/images/ws-view-menu.png
)

set(WSDG_TITLE "Wireshark Developer's Guide")

set(WSDG_FILES
	wsdg_src/wsdg_asn2wrs.adoc
	wsdg_src/wsdg_build_intro.adoc
	wsdg_src/wsdg_capture.adoc
	wsdg_src/wsdg_dissection.adoc
	wsdg_src/wsdg_env_intro.adoc
	wsdg_src/wsdg_libraries.adoc
	wsdg_src/wsdg_lua_support.adoc
	wsdg_src/wsdg_preface.adoc
	wsdg_src/wsdg_quick_setup.adoc
	wsdg_src/wsdg_sources.adoc
	wsdg_src/wsdg_tests.adoc
	wsdg_src/wsdg_tools.adoc
	wsdg_src/wsdg_userinterface.adoc
	wsdg_src/wsdg_works.adoc
	${COMMON_FILES}
)

set(WSDG_GRAPHICS
	wsdg_src/images/caution.svg
	wsdg_src/images/git-triangular-workflow.gv
	wsdg_src/images/git-triangular-workflow.svg
	wsdg_src/images/important.svg
	wsdg_src/images/note.svg
	wsdg_src/images/tip.svg
	wsdg_src/images/warning.svg
	wsdg_src/images/ws-capture_internals.dia
	wsdg_src/images/ws-capture_internals.png
	wsdg_src/images/ws-capture-sync.dia
	wsdg_src/images/ws-capture-sync.png
	wsdg_src/images/ws-capture-sync.png
	wsdg_src/images/ws-function-blocks.dia
	wsdg_src/images/ws-function-blocks.svg
	wsdg_src/images/ws-logo.png
)

set(WSUG_SOURCE
	${WSUG_FILES}
	${WSUG_GRAPHICS}
)

# Ensure ws.css is available when the user tries to open generated .html files.
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	add_custom_command(
		OUTPUT ws.css
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			${CMAKE_SOURCE_DIR}/doc/ws.css
			${CMAKE_CURRENT_BINARY_DIR}/ws.css
		DEPENDS
			${CMAKE_SOURCE_DIR}/doc/ws.css
	)
	add_custom_target(copy_ws.css DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/ws.css)
else()
	add_custom_target(copy_ws.css)
endif()

set( WSUG_BUILT_DEPS copy_ws.css)

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
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_wtap.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_utility.c
	${CMAKE_SOURCE_DIR}/epan/wslua/wslua_struct.c
)

# Empty file to trigger wsluarm generation.
ADD_CUSTOM_COMMAND(
	OUTPUT
		wsluarm
	COMMAND ${CMAKE_COMMAND} -E make_directory wsluarm_src
	COMMAND ${Python3_EXECUTABLE}
		${CMAKE_CURRENT_SOURCE_DIR}/make-wsluarm.py
		--output-directory wsluarm_src
		${WSLUA_MODULES}
	COMMAND ${CMAKE_COMMAND} -E touch
		wsluarm
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/make-wsluarm.py
		${WSLUA_MODULES}
)

set( WSDG_BUILT_DEPS copy_ws.css wsluarm )

set( ASCIIDOC_CONF_FILES
	${CMAKE_SOURCE_DIR}/doc/attributes.adoc
	# XXX Add macros
)

if(ASCIIDOCTOR_FOUND)
	# Generate the DocBook sources of user and developer guides

	ASCIIDOCTOR2DOCBOOK(wsug_src/user-guide.adoc ${ASCIIDOC_CONF_FILES} ${WSUG_SOURCE} ${WSUG_BUILT_DEPS})
	add_custom_target(user_guide_docbook DEPENDS generate_user-guide.xml)
	set_docbook_target_properties(user_guide_docbook)

	ASCIIDOCTOR2DOCBOOK(wsdg_src/developer-guide.adoc ${ASCIIDOC_CONF_FILES} ${WSDG_SOURCE} ${WSDG_BUILT_DEPS})
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
if(ASCIIDOCTOR_FOUND AND XSLTPROC_EXECUTABLE)
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
	# Copy the WSUG to the build directory so that when running
	# from the build directory ui/help_url.c will find the local file.
	# It expects the WSUG in a different directory on Windows.
	if(WIN32)
		set(WSUG_DIR "${DATAFILE_DIR}/${WSUG_TITLE}")
	else()
		set(WSUG_DIR "${DATAFILE_DIR}/wsug_html_chunked")
	endif()
	# CMake 3.26 has copy_directory_if_different
	add_custom_command(
		TARGET user_guide_html
		COMMAND ${CMAKE_COMMAND} -E copy_directory
			"${CMAKE_CURRENT_BINARY_DIR}/wsug_html_chunked" "${WSUG_DIR}"
		VERBATIM
	)
endif()

if(ASCIIDOCTOR_FOUND AND ASCIIDOCTOR_PDF_EXECUTABLE)
	ASCIIDOCTOR2PDF(${WSUG_TITLE} wsug_src/user-guide.adoc ${WSUG_SOURCE} ${WSUG_BUILT_DEPS})

	add_custom_target(
		user_guide_pdf
		DEPENDS
			"${WSUG_TITLE}.pdf"
	)
	set_docbook_target_properties(user_guide_pdf)
	add_dependencies(user_guides user_guide_pdf)
endif()

if(ASCIIDOCTOR_FOUND AND ASCIIDOCTOR_EPUB_EXECUTABLE)
	ASCIIDOCTOR2EPUB(${WSUG_TITLE} wsug_src/user-guide.adoc ${WSUG_SOURCE} ${WSUG_BUILT_DEPS})

	add_custom_target(
		user_guide_epub
		DEPENDS
			"${WSUG_TITLE}.epub"
	)
	set_docbook_target_properties(user_guide_epub)
	add_dependencies(user_guides user_guide_epub)
endif()

# Developer's Guide chain.
if(ASCIIDOCTOR_FOUND AND XSLTPROC_EXECUTABLE)
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
endif()

if(ASCIIDOCTOR_FOUND AND ASCIIDOCTOR_PDF_EXECUTABLE)
	ASCIIDOCTOR2PDF(${WSDG_TITLE} wsdg_src/developer-guide.adoc ${WSDG_SOURCE} ${WSDG_BUILT_DEPS})

	add_custom_target(
		developer_guide_pdf
		DEPENDS
			"${WSDG_TITLE}.pdf"
	)
	set_docbook_target_properties(developer_guide_pdf)
	add_dependencies(developer_guides developer_guide_pdf)
endif()

if(ASCIIDOCTOR_FOUND AND ASCIIDOCTOR_EPUB_EXECUTABLE)
	ASCIIDOCTOR2EPUB(${WSDG_TITLE} wsdg_src/developer-guide.adoc ${WSDG_SOURCE} ${WSDG_BUILT_DEPS})

	add_custom_target(
		developer_guide_epub
		DEPENDS
			"${WSDG_TITLE}.epub"
	)
	set_docbook_target_properties(developer_guide_epub)
	add_dependencies(developer_guides developer_guide_epub)
endif()

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
