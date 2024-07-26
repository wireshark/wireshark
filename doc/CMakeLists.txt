# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

find_package( Asciidoctor 1.5 )

function(set_doc_target_properties _target)
	set_target_properties(${_target} PROPERTIES
		FOLDER "Documentation"
		EXCLUDE_FROM_DEFAULT_BUILD True
		)
endfunction()

set(MAN1_SOURCE_FILES)
set(MAN4_SOURCE_FILES)
set(MAN1_INSTALL_FILES)
set(MAN4_INSTALL_FILES)
set(HTML_INSTALL_FILES)

macro (ADD_MAN_PAGE _page_name _man_section)
	if(ASCIIDOCTOR_FOUND)
		list(APPEND HTML_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/man_pages/${_page_name}.html)

		if (${_man_section} EQUAL 1)
			list(APPEND MAN1_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/man_pages/${_page_name}.adoc)
			list(APPEND MAN1_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/man_pages/${_page_name}.${_man_section})
		elseif (${_man_section} EQUAL 4)
			list(APPEND MAN4_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/man_pages/${_page_name}.adoc)
			list(APPEND MAN4_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/man_pages/${_page_name}.${_man_section})
		else()
			message(FATAL_ERROR "Unsupported manual page section ${_man_section} for ${_page_name}")
		endif()
	endif()
endmacro()

ADD_MAN_PAGE(wireshark   1)
ADD_MAN_PAGE(androiddump 1)
ADD_MAN_PAGE(capinfos    1)
ADD_MAN_PAGE(captype     1)
ADD_MAN_PAGE(ciscodump   1)
ADD_MAN_PAGE(dumpcap     1)
ADD_MAN_PAGE(editcap     1)
ADD_MAN_PAGE(mergecap    1)
ADD_MAN_PAGE(randpkt     1)
ADD_MAN_PAGE(randpktdump 1)
ADD_MAN_PAGE(etwdump     1)
ADD_MAN_PAGE(rawshark    1)
ADD_MAN_PAGE(reordercap  1)
ADD_MAN_PAGE(sshdump     1)
ADD_MAN_PAGE(text2pcap   1)
ADD_MAN_PAGE(tshark      1)
ADD_MAN_PAGE(falcodump   1)
ADD_MAN_PAGE(udpdump     1)
ADD_MAN_PAGE(wifidump    1)

ADD_MAN_PAGE(extcap           4)
ADD_MAN_PAGE(wireshark-filter 4)

if(BUILD_dpauxmon AND HAVE_LIBNL3)
	ADD_MAN_PAGE(dpauxmon    1)
endif()

if(BUILD_sdjournal AND SYSTEMD_FOUND)
	ADD_MAN_PAGE(sdjournal   1)
endif()

if(MAXMINDDB_FOUND)
	ADD_MAN_PAGE(mmdbresolve 1)
endif()

if (BUILD_corbaidl2wrs)
	ADD_MAN_PAGE(idl2wrs     1)
endif()

if (BUILD_xxx2deb)
	ADD_MAN_PAGE(asn2deb     1)
	ADD_MAN_PAGE(idl2deb     1)
endif()

set(WIRESHARK_BUNDLE_RESOURCE_SHARE_MAN1_FILES ${MAN1_INSTALL_FILES} PARENT_SCOPE)
set(WIRESHARK_BUNDLE_RESOURCE_SHARE_MAN4_FILES ${MAN4_INSTALL_FILES} PARENT_SCOPE)
# XXX We need a Logray-specific man page list, which might overlap with Wireshark's.
# Just install everything for now.
set(LOGRAY_BUNDLE_RESOURCE_SHARE_MAN1_FILES ${WIRESHARK_BUNDLE_RESOURCE_SHARE_MAN1_FILES} PARENT_SCOPE)
set(LOGRAY_BUNDLE_RESOURCE_SHARE_MAN4_FILES ${WIRESHARK_BUNDLE_RESOURCE_SHARE_MAN4_FILES} PARENT_SCOPE)

set(MAN_INCLUDES man_pages/diagnostic-options.adoc man_pages/dissection-options.adoc man_pages/files.adoc)

if(ASCIIDOCTOR_FOUND)
	ASCIIDOCTOR2ROFFMAN(1 ${MAN1_SOURCE_FILES})
	ASCIIDOCTOR2ROFFMAN(4 ${MAN4_SOURCE_FILES})
	ASCIIDOCTOR2HTMLMAN(${MAN1_SOURCE_FILES} ${MAN4_SOURCE_FILES})

	add_custom_target(manpages
		DEPENDS
			${MAN1_INSTALL_FILES}
			${MAN4_INSTALL_FILES}
	)
	set_target_properties(manpages PROPERTIES FOLDER "Documentation")
endif()

if(ASCIIDOCTOR_FOUND)
	ASCIIDOCTOR2HTML(release-notes.adoc)
	ASCIIDOCTOR2TXT(release-notes.adoc)

	add_custom_target(release_notes_html
		DEPENDS
			${CMAKE_CURRENT_BINARY_DIR}/release-notes.html
	)
	set_target_properties(release_notes_html PROPERTIES FOLDER "Documentation")

	add_custom_target(release_notes_txt
		DEPENDS
			${CMAKE_CURRENT_BINARY_DIR}/release-notes.txt
			release_notes_html
	)
	set_target_properties(release_notes_txt PROPERTIES FOLDER "Documentation")

	add_custom_target(release_notes
		DEPENDS
			release_notes_html
			release_notes_txt
	)
	set_target_properties(release_notes PROPERTIES FOLDER "Documentation")

	ASCIIDOCTOR2HTML(faq.adoc)
	add_custom_target(faq_html DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/faq.html)
	set_doc_target_properties(faq_html)

	add_custom_target(faq DEPENDS faq_html)
	set_doc_target_properties(faq)
endif()


add_custom_target(docs
	DEPENDS
		${HTML_INSTALL_FILES}
)
set_target_properties(docs PROPERTIES FOLDER "Documentation")

if(ASCIIDOCTOR_FOUND)
	add_dependencies(docs manpages release_notes_html)

	install(
		FILES
			${MAN1_INSTALL_FILES}
		DESTINATION
			${CMAKE_INSTALL_MANDIR}/man1
	)

	install(
		FILES
			${MAN4_INSTALL_FILES}
		DESTINATION
			${CMAKE_INSTALL_MANDIR}/man4
	)


	install(
		FILES
			${HTML_INSTALL_FILES}
			${CMAKE_CURRENT_BINARY_DIR}/release-notes.html
		DESTINATION
			${CMAKE_INSTALL_DOCDIR}
		COMPONENT "ReleaseNotes"
	)
endif()

#
# Wireshark User's and Developer's Guides
#

set(COMMON_GUIDE_FILES
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
	${COMMON_GUIDE_FILES}
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
	${COMMON_GUIDE_FILES}
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
		${CMAKE_SOURCE_DIR}/tools/make-wsluarm.py
		--output-directory wsluarm_src
		${WSLUA_MODULES}
	COMMAND ${CMAKE_COMMAND} -E touch
		wsluarm
	DEPENDS
		${CMAKE_SOURCE_DIR}/tools/make-wsluarm.py
		${WSLUA_MODULES}
)

set( WSDG_BUILT_DEPS wsluarm )

set( ASCIIDOC_CONF_FILES
	${CMAKE_CURRENT_SOURCE_DIR}/attributes.adoc
	# XXX Add macros
)

if(ASCIIDOCTOR_FOUND)
	# Generate the DocBook sources of user and developer guides

	ASCIIDOCTOR2DOCBOOK(wsug_src/user-guide.adoc ${ASCIIDOC_CONF_FILES} ${WSUG_SOURCE} ${WSUG_BUILT_DEPS})
	add_custom_target(user_guide_docbook DEPENDS generate_user-guide.xml)
	set_doc_target_properties(user_guide_docbook)
	set_target_properties(user_guide_docbook PROPERTIES EXCLUDE_FROM_ALL True)

	ASCIIDOCTOR2DOCBOOK(wsdg_src/developer-guide.adoc ${ASCIIDOC_CONF_FILES} ${WSDG_SOURCE} ${WSDG_BUILT_DEPS})
	add_custom_target(developer_guide_docbook DEPENDS generate_developer-guide.xml)
	set_doc_target_properties(developer_guide_docbook)
	set_target_properties(developer_guide_docbook PROPERTIES EXCLUDE_FROM_ALL True)

	# Top-level guide targets.

	add_custom_target(user_guides DEPENDS user_guide_docbook)
	set_doc_target_properties(user_guides)
	set_target_properties(user_guides PROPERTIES EXCLUDE_FROM_ALL True)

	add_custom_target(developer_guides DEPENDS developer_guide_docbook)
	set_doc_target_properties(developer_guides)
	set_target_properties(developer_guides PROPERTIES EXCLUDE_FROM_ALL True)

	add_custom_target(all_guides DEPENDS user_guides developer_guides )
	set_doc_target_properties(all_guides)
	set_target_properties(all_guides PROPERTIES EXCLUDE_FROM_ALL True)
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
	add_custom_target(user_guide_html
		DEPENDS
			wsug_html/index.html
			wsug_html_chunked/index.html
	)
	set_doc_target_properties(user_guide_html)
	set_target_properties(user_guide_html PROPERTIES EXCLUDE_FROM_ALL True)
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

	add_custom_target(user_guide_pdf
		DEPENDS
			"${WSUG_TITLE}.pdf"
	)
	set_doc_target_properties(user_guide_pdf)
	set_target_properties(user_guide_pdf PROPERTIES EXCLUDE_FROM_ALL True)
	add_dependencies(user_guides user_guide_pdf)
endif()

if(ASCIIDOCTOR_FOUND AND ASCIIDOCTOR_EPUB_EXECUTABLE)
	ASCIIDOCTOR2EPUB(${WSUG_TITLE} wsug_src/user-guide.adoc ${WSUG_SOURCE} ${WSUG_BUILT_DEPS})

	add_custom_target(user_guide_epub
		DEPENDS
			"${WSUG_TITLE}.epub"
	)
	set_doc_target_properties(user_guide_epub)
	set_target_properties(user_guide_epub PROPERTIES EXCLUDE_FROM_ALL True)
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
	add_custom_target(developer_guide_html
		DEPENDS
			wsdg_html/index.html
			wsdg_html_chunked/index.html
	)
	set_doc_target_properties(developer_guide_html)
	set_target_properties(developer_guide_html PROPERTIES EXCLUDE_FROM_ALL True)
	add_dependencies(developer_guides developer_guide_html)
endif()

if(ASCIIDOCTOR_FOUND AND ASCIIDOCTOR_PDF_EXECUTABLE)
	ASCIIDOCTOR2PDF(${WSDG_TITLE} wsdg_src/developer-guide.adoc ${WSDG_SOURCE} ${WSDG_BUILT_DEPS})

	add_custom_target(developer_guide_pdf
		DEPENDS
			"${WSDG_TITLE}.pdf"
	)
	set_doc_target_properties(developer_guide_pdf)
	set_target_properties(developer_guide_pdf PROPERTIES EXCLUDE_FROM_ALL True)
	add_dependencies(developer_guides developer_guide_pdf)
endif()

if(ASCIIDOCTOR_FOUND AND ASCIIDOCTOR_EPUB_EXECUTABLE)
	ASCIIDOCTOR2EPUB(${WSDG_TITLE} wsdg_src/developer-guide.adoc ${WSDG_SOURCE} ${WSDG_BUILT_DEPS})

	add_custom_target(developer_guide_epub
		DEPENDS
			"${WSDG_TITLE}.epub"
	)
	set_doc_target_properties(developer_guide_epub)
	set_target_properties(developer_guide_epub PROPERTIES EXCLUDE_FROM_ALL True)
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
