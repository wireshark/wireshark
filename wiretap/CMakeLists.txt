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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


set(WIRETAP_FILES
	5views.c
	aethra.c
	ascendtext.c
	atm.c
	ber.c
	btsnoop.c
	buffer.c
	camins.c
	catapult_dct2000.c
	commview.c
	cosine.c
	csids.c
	daintree-sna.c
	dbs-etherwatch.c
	dct3trace.c
	erf.c
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
	peekclassic.c
	peektagged.c
	pppdump.c
	radcom.c
	snoop.c
	tnef.c
	toshiba.c
	visual.c
	vms.c
	vwr.c
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

set(FULL_SO_VERSION "3.0.2")

set_target_properties(wiretap PROPERTIES COMPILE_DEFINITIONS "WS_BUILD_DLL")
set_target_properties(wiretap PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
set_target_properties(wiretap PROPERTIES VERSION ${FULL_SO_VERSION} SOVERSION 3)

# discover and substitute list of include directories for ABI compatibility
# checks
get_directory_property(INCLUDE_DIRS INCLUDE_DIRECTORIES)
list(REMOVE_DUPLICATES INCLUDE_DIRS)
string(REGEX REPLACE ";" "\n" INCLUDE_DIRS "${INCLUDE_DIRS}")
configure_file(../abi-descriptor.template abi-descriptor.xml)

# ABI compliance checker can be obtained from
# http://ispras.linux-foundation.org/index.php/ABI_compliance_checker
# Checked using version 1.21.12
file(GLOB HEADERS *.h)
file(MAKE_DIRECTORY abi-check-headers)

file(COPY ${HEADERS} ../ws_symbol_export.h DESTINATION abi-check-headers)

add_custom_command(OUTPUT libwiretap.abi.tar.gz
	COMMAND cp ../config.h abi-check-headers/
	COMMAND abi-compliance-checker -l libwiretap -v1 ${FULL_SO_VERSION}
		-relpath ${CMAKE_CURRENT_BINARY_DIR} -dump-abi abi-descriptor.xml
		|| cat logs/libwiretap/[0-9]*/log.txt
	COMMAND cp abi_dumps/libwiretap/libwiretap_* libwiretap.abi.tar.gz
	COMMAND rm -rf abi-check-headers/* abi_dumps
	DEPENDS ${HEADERS} wiretap)
add_custom_target(dumpabi-libwiretap DEPENDS libwiretap.abi.tar.gz)

target_link_libraries(wiretap ${wiretap_LIBS})

if(NOT ${ENABLE_STATIC})
	install(TARGETS wiretap
		LIBRARY DESTINATION lib
		RUNTIME DESTINATION lib
		ARCHIVE DESTINATION lib
	)
endif()

