# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

find_package( Asciidoctor 1.5 )

add_custom_command(
	OUTPUT AUTHORS-SHORT
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_CURRENT_SOURCE_DIR}/make-authors-short.pl
		< ${CMAKE_SOURCE_DIR}/AUTHORS
		> ${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/make-authors-short.pl
		${CMAKE_SOURCE_DIR}/AUTHORS
)

set(MAN1_INSTALL_FILES)
set(MAN4_INSTALL_FILES)
set(HTML_INSTALL_FILES)
set(GENERATOR_TARGETS)

macro (ASCIIDOCTOR2MANHTML _page_name _man_section)
	if(ASCIIDOCTOR_FOUND)
		ASCIIDOCTOR2HTML(${_page_name}.adoc)
		list(APPEND GENERATOR_TARGETS generate_${_page_name}.html)
		# Override set_asciidoctor_target_properties
		set_target_properties(generate_${_page_name}.html PROPERTIES
			FOLDER "Docs"
			EXCLUDE_FROM_DEFAULT_BUILD False
		)
		list(APPEND HTML_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/${_page_name}.html)

		ASCIIDOCTOR2MAN(${_page_name}.adoc ${_man_section})
		list(APPEND GENERATOR_TARGETS generate_${_page_name}.${_man_section})
		set_target_properties(generate_${_page_name}.${_man_section} PROPERTIES
			FOLDER "Docs"
			EXCLUDE_FROM_DEFAULT_BUILD False
		)
		if (${_man_section} EQUAL 1)
			list(APPEND MAN1_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/${_page_name}.${_man_section})
		elseif (${_man_section} EQUAL 4)
			list(APPEND MAN4_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/${_page_name}.${_man_section})
		else()
			message(FATAL_ERROR "Unsupported manual page section ${_man_section} for ${_page_name}")
		endif()
	endif()
endmacro()

ASCIIDOCTOR2MANHTML(wireshark   1)
ASCIIDOCTOR2MANHTML(androiddump 1)
ASCIIDOCTOR2MANHTML(capinfos    1)
ASCIIDOCTOR2MANHTML(captype     1)
ASCIIDOCTOR2MANHTML(ciscodump   1)
ASCIIDOCTOR2MANHTML(dftest      1)
ASCIIDOCTOR2MANHTML(dumpcap     1)
ASCIIDOCTOR2MANHTML(editcap     1)
ASCIIDOCTOR2MANHTML(mergecap    1)
ASCIIDOCTOR2MANHTML(randpkt     1)
ASCIIDOCTOR2MANHTML(randpktdump 1)
ASCIIDOCTOR2MANHTML(etwdump     1)
ASCIIDOCTOR2MANHTML(rawshark    1)
ASCIIDOCTOR2MANHTML(reordercap  1)
ASCIIDOCTOR2MANHTML(sshdump     1)
ASCIIDOCTOR2MANHTML(text2pcap   1)
ASCIIDOCTOR2MANHTML(tshark      1)
ASCIIDOCTOR2MANHTML(udpdump     1)

ASCIIDOCTOR2MANHTML(extcap           4)
ASCIIDOCTOR2MANHTML(wireshark-filter 4)

if(BUILD_dpauxmon AND HAVE_LIBNL3)
	ASCIIDOCTOR2MANHTML(dpauxmon    1)
endif()

if(BUILD_sdjournal AND SYSTEMD_FOUND)
	ASCIIDOCTOR2MANHTML(sdjournal   1)
endif()

if(MAXMINDDB_FOUND)
	ASCIIDOCTOR2MANHTML(mmdbresolve 1)
endif()

if (BUILD_corbaidl2wrs)
	ASCIIDOCTOR2MANHTML(idl2wrs     1)
endif()

if (BUILD_xxx2deb)
	ASCIIDOCTOR2MANHTML(asn2deb     1)
	ASCIIDOCTOR2MANHTML(idl2deb     1)
endif()

set(BUNDLE_RESOURCE_SHARE_MAN1_FILES ${MAN1_INSTALL_FILES} PARENT_SCOPE)
set(BUNDLE_RESOURCE_SHARE_MAN4_FILES ${MAN4_INSTALL_FILES} PARENT_SCOPE)

add_custom_target(manpages DEPENDS
	${MAN1_INSTALL_FILES}
	${MAN4_INSTALL_FILES}
)

add_custom_target(
	docs ALL
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT
		${GENERATOR_TARGETS}
		${MAN1_INSTALL_FILES}
		${MAN4_INSTALL_FILES}
		${HTML_INSTALL_FILES}
)
set_target_properties(docs PROPERTIES FOLDER "Docs")

if(ASCIIDOCTOR_FOUND)
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
endif()

#
# Installation of HTML manuals is done
# elsewhere to CMAKE_INSTALL_DATADIR.
#

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
