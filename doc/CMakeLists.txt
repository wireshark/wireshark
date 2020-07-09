# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

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

add_custom_command(
	OUTPUT AUTHORS-SHORT-FORMAT
	COMMAND ${PERL_EXECUTABLE}
		${CMAKE_CURRENT_SOURCE_DIR}/make-authors-format.pl
		< ${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT
		> ${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT-FORMAT
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/make-authors-format.pl
		${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT
)

if(WIN32)
	file(TO_NATIVE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/wireshark.pod.template WPT_WIN_PATH)
	file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT-FORMAT ASF_WIN_PATH)
	file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}/wireshark.pod WP_WIN_PATH)
	add_custom_command(
		OUTPUT wireshark.pod
		COMMAND copy /B ${WPT_WIN_PATH} + ${ASF_WIN_PATH} ${WP_WIN_PATH}
		DEPENDS
			${CMAKE_CURRENT_SOURCE_DIR}/wireshark.pod.template
			${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT-FORMAT
	)
else()
	add_custom_command(
		OUTPUT wireshark.pod
		COMMAND cat
			${CMAKE_CURRENT_SOURCE_DIR}/wireshark.pod.template
			${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT-FORMAT
			> ${CMAKE_CURRENT_BINARY_DIR}/wireshark.pod
		DEPENDS
			${CMAKE_CURRENT_SOURCE_DIR}/wireshark.pod.template
			${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT-FORMAT
	)
endif()

pod2manhtml(${CMAKE_CURRENT_BINARY_DIR}/wireshark   1)

pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/androiddump 1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/capinfos    1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/captype     1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/ciscodump   1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/dftest      1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/dumpcap     1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/editcap     1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/mergecap    1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/randpkt     1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/randpktdump 1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/rawshark    1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/reordercap  1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/sshdump     1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/text2pcap   1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/tshark      1)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/udpdump     1)

pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/extcap           4)
pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/wireshark-filter 4)

if(BUILD_dpauxmon AND HAVE_LIBNL3)
	pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/dpauxmon    1)
endif()

if(BUILD_sdjournal AND SYSTEMD_FOUND)
	pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/sdjournal   1)
endif()

if(MAXMINDDB_FOUND)
	pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/mmdbresolve 1)
endif()

if (BUILD_corbaidl2wrs)
	pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/idl2wrs     1)
endif()
if (BUILD_xxx2deb)
	pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/asn2deb     1)
	pod2manhtml(${CMAKE_CURRENT_SOURCE_DIR}/idl2deb     1)
endif()

set(MAN1_INSTALL_FILES
	${CMAKE_CURRENT_BINARY_DIR}/androiddump.1
	${CMAKE_CURRENT_BINARY_DIR}/capinfos.1
	${CMAKE_CURRENT_BINARY_DIR}/captype.1
	${CMAKE_CURRENT_BINARY_DIR}/ciscodump.1
	${CMAKE_CURRENT_BINARY_DIR}/ciscodump.1
	${CMAKE_CURRENT_BINARY_DIR}/dftest.1
	${CMAKE_CURRENT_BINARY_DIR}/dumpcap.1
	${CMAKE_CURRENT_BINARY_DIR}/editcap.1
	${CMAKE_CURRENT_BINARY_DIR}/mergecap.1
	${CMAKE_CURRENT_BINARY_DIR}/randpkt.1
	${CMAKE_CURRENT_BINARY_DIR}/randpktdump.1
	${CMAKE_CURRENT_BINARY_DIR}/rawshark.1
	${CMAKE_CURRENT_BINARY_DIR}/reordercap.1
	${CMAKE_CURRENT_BINARY_DIR}/sshdump.1
	${CMAKE_CURRENT_BINARY_DIR}/text2pcap.1
	${CMAKE_CURRENT_BINARY_DIR}/tshark.1
	${CMAKE_CURRENT_BINARY_DIR}/udpdump.1
	${CMAKE_CURRENT_BINARY_DIR}/wireshark.1
)

if(BUILD_dpauxmon AND HAVE_LIBNL3)
	list(APPEND MAN1_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/dpauxmon.1)
endif()

if(BUILD_sdjournal AND SYSTEMD_FOUND)
	list(APPEND MAN1_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/sdjournal.1)
endif()

if(MAXMINDDB_FOUND)
	list(APPEND MAN1_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/mmdbresolve.1)
endif()

if (BUILD_corbaidl2wrs)
	list(APPEND MAN1_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/idl2wrs.1)
endif()
if (BUILD_xxx2deb)
	list(APPEND MAN1_INSTALL_FILES
		${CMAKE_CURRENT_BINARY_DIR}/asn2deb.1
		${CMAKE_CURRENT_BINARY_DIR}/idl2deb.1
	)
endif()

set(MAN4_INSTALL_FILES
	${CMAKE_CURRENT_BINARY_DIR}/extcap.4
	${CMAKE_CURRENT_BINARY_DIR}/wireshark-filter.4
)

set(BUNDLE_RESOURCE_SHARE_MAN1_FILES ${MAN1_INSTALL_FILES} PARENT_SCOPE)
set(BUNDLE_RESOURCE_SHARE_MAN4_FILES ${MAN4_INSTALL_FILES} PARENT_SCOPE)

add_custom_target(manpages DEPENDS
	${MAN1_INSTALL_FILES}
	${MAN4_INSTALL_FILES}
)

set(HTML_INSTALL_FILES
	${CMAKE_CURRENT_BINARY_DIR}/androiddump.html
	${CMAKE_CURRENT_BINARY_DIR}/capinfos.html
	${CMAKE_CURRENT_BINARY_DIR}/captype.html
	${CMAKE_CURRENT_BINARY_DIR}/ciscodump.html
	${CMAKE_CURRENT_BINARY_DIR}/ciscodump.html
	${CMAKE_CURRENT_BINARY_DIR}/dftest.html
	${CMAKE_CURRENT_BINARY_DIR}/dumpcap.html
	${CMAKE_CURRENT_BINARY_DIR}/editcap.html
	${CMAKE_CURRENT_BINARY_DIR}/extcap.html
	${CMAKE_CURRENT_BINARY_DIR}/mergecap.html
	${CMAKE_CURRENT_BINARY_DIR}/randpkt.html
	${CMAKE_CURRENT_BINARY_DIR}/randpktdump.html
	${CMAKE_CURRENT_BINARY_DIR}/rawshark.html
	${CMAKE_CURRENT_BINARY_DIR}/reordercap.html
	${CMAKE_CURRENT_BINARY_DIR}/sshdump.html
	${CMAKE_CURRENT_BINARY_DIR}/text2pcap.html
	${CMAKE_CURRENT_BINARY_DIR}/tshark.html
	${CMAKE_CURRENT_BINARY_DIR}/udpdump.html
	${CMAKE_CURRENT_BINARY_DIR}/wireshark-filter.html
	${CMAKE_CURRENT_BINARY_DIR}/wireshark.html
)

if(BUILD_dpauxmon AND HAVE_LIBNL3)
	list(APPEND HTML_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/dpauxmon.html)
endif()

if(BUILD_sdjournal AND SYSTEMD_FOUND)
	list(APPEND HTML_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/sdjournal.html)
endif()

if(MAXMINDDB_FOUND)
	list(APPEND HTML_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/mmdbresolve.html)
endif()

if (BUILD_corbaidl2wrs)
	list(APPEND HTML_INSTALL_FILES ${CMAKE_CURRENT_BINARY_DIR}/idl2wrs.html)
endif()
if (BUILD_xxx2deb)
	list(APPEND HTML_INSTALL_FILES
		${CMAKE_CURRENT_BINARY_DIR}/asn2deb.html
		${CMAKE_CURRENT_BINARY_DIR}/idl2deb.html
	)
endif()

add_custom_target(
	docs ALL
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT
		${CMAKE_CURRENT_BINARY_DIR}/AUTHORS-SHORT-FORMAT
		${MAN1_INSTALL_FILES}
		${MAN4_INSTALL_FILES}
		${HTML_INSTALL_FILES}
)
set_target_properties(docs PROPERTIES FOLDER "Docs")

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
	DESTINATION
		${CMAKE_INSTALL_DOCDIR}
)

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
