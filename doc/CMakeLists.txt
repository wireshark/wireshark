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

	add_custom_target(manpages DEPENDS
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

	add_custom_target(news
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			${CMAKE_CURRENT_BINARY_DIR}/release-notes.txt
			${CMAKE_SOURCE_DIR}/NEWS
		DEPENDS
			release_notes_txt
	)
	set_target_properties(news PROPERTIES FOLDER "Documentation")

	ASCIIDOCTOR2HTML(faq.adoc)
	add_custom_target(faq_html DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/faq.html)
	set_doc_target_properties(faq_html)

	add_custom_target(faq)
	set_doc_target_properties(faq)
	add_dependencies (faq faq_html)
endif()


add_custom_target(
	docs ALL
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
	)
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
