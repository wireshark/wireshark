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

include(UseABICheck)

set(WIRETAP_FILES
	5views.c
	aethra.c
	ascendtext.c
	atm.c
	ber.c
	btsnoop.c
	camins.c
	capsa.c
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
	json.c
	k12.c
	lanalyzer.c
	libpcap.c
	logcat.c
	logcat_text.c
	merge.c
	mpeg.c
	mime_file.c
	mp2t.c
	netmon.c
	netscaler.c
	netscreen.c
	nettl.c
	nettrace_3gpp_32_423.c
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
	stanag4607.c
	tnef.c
	toshiba.c
	visual.c
	vms.c
	vwr.c
	wtap.c
)

if (WERROR)
	set_source_files_properties(
		${WIRETAP_FILES}
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
	${CMAKE_BINARY_DIR}/image/wiretap.rc
)

set(FULL_SO_VERSION "0.0.7")

set_target_properties(wiretap PROPERTIES
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
	LINK_FLAGS "${WS_LINK_FLAGS}"
	VERSION ${FULL_SO_VERSION} SOVERSION 0
	FOLDER "DLLs"
)
IF(MSVC)
	set_target_properties(wiretap PROPERTIES OUTPUT_NAME "wiretap-${PROJECT_VERSION}")
ENDIF()

if(ENABLE_APPLICATION_BUNDLE)
	set_target_properties(wiretap PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/run/Wireshark.app/Contents/Frameworks
	)
endif()

ABICHECK(libwiretap)

add_custom_command(OUTPUT libwiretap.abi.tar.gz
	COMMAND cp ../config.h ${ABICHECK_TMPDIR}/
	COMMAND ${ABICHECK_COMMAND}
	COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps/libwiretap/libwiretap_* ${CMAKE_CURRENT_BINARY_DIR}/libwiretap.abi.tar.gz
	COMMAND rm -rf ${ABICHECK_TMPDIR}/* ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps
	DEPENDS ${HEADERS} wiretap)

target_link_libraries(wiretap ${wiretap_LIBS})

if(NOT ${ENABLE_STATIC})
	install(TARGETS wiretap
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	)
endif()
