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


set(WIRETAP_FILES
	5views.c
	aethra.c
	airopeek9.c
	ascendtext.c
	atm.c
	ber.c
	btsnoop.c
	buffer.c
	catapult_dct2000.c
	commview.c
	cosine.c
	csids.c
	daintree-sna.c
	dbs-etherwatch.c
	dct3trace.c
	erf.c
	etherpeek.c
	eyesdn.c
	file_access.c
	file_wrappers.c
	hcidump.c
	i4btrace.c
	ipfix.c
	iptrace.c
	iseries.c
	k12.c
	lanalyzer.c
	libpcap.c
	mpeg.c
	mime_file.c
	mp2t.c
	netmon.c
	netscaler.c
	netscreen.c
	nettl.c
	network_instruments.c
	netxray.c
	ngsniffer.c
	packetlogger.c
	pcap-common.c
	pcapng.c
	pppdump.c
	radcom.c
	snoop.c
	tnef.c
	toshiba.c
	visual.c
	vms.c
	wtap.c
)

set(CLEAN_FILES
	${WIRETAP_FILES}
)

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

add_lex_files(WIRETAP_FILES
	ascend_scanner.l
	k12text.l
)

add_yacc_files(WIRETAP_FILES
	ascend.y
)

set(wiretap_LIBS
	${GLIB2_LIBRARIES}
	${GMODULE2_LIBRARIES}
	${ZLIB_LIBRARIES}
	wsutil
)

add_library(wiretap ${LINK_MODE_LIB}
	${WIRETAP_FILES}
)
set_target_properties(wiretap PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

target_link_libraries(wiretap ${wiretap_LIBS})

if(NOT ${ENABLE_STATIC})
	install(TARGETS wiretap
		LIBRARY DESTINATION lib
		RUNTIME DESTINATION lib
		ARCHIVE DESTINATION lib
	)
endif()

