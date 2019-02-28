# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(UseABICheck)

set(WIRETAP_PUBLIC_HEADERS
	file_wrappers.h
	merge.h
	pcap-encap.h
	pcapng_module.h
	secrets-types.h
	wtap.h
	wtap_opttypes.h
)

set(WIRETAP_NONGENERATED_FILES
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
	dpa400.c
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
	mplog.c
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
	rfc7468.c
	pppdump.c
	radcom.c
	ruby_marshal.c
	snoop.c
	stanag4607.c
	systemd_journal.c
	tnef.c
	toshiba.c
	visual.c
	vms.c
	vwr.c
	wtap.c
	wtap_opttypes.c
)

set(WIRETAP_FILES ${WIRETAP_NONGENERATED_FILES})

add_lex_files(LEX_FILES WIRETAP_FILES
	ascend_scanner.l
	k12text.l
)

add_yacc_files(YACC_FILES WIRETAP_FILES
	ascend.y
)

#
# All files are warning-clean.  (Let's keep it that way.)
#
set_source_files_properties(
	${WIRETAP_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

add_library(wiretap
	${WIRETAP_FILES}
	${CMAKE_BINARY_DIR}/image/wiretap.rc
)

set_target_properties(wiretap PROPERTIES
	PREFIX "lib"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
	LINK_FLAGS "${WS_LINK_FLAGS}"
	VERSION "9.0.1" SOVERSION 9
	FOLDER "DLLs"
	INSTALL_RPATH "${LIBRARY_INSTALL_RPATH}"
)

ABICHECK(libwiretap)

add_custom_command(OUTPUT libwiretap.abi.tar.gz
	COMMAND ${CMAKE_COMMAND} -E remove_directory ${ABICHECK_TMPDIR}
	COMMAND ${CMAKE_COMMAND} -E make_directory ${ABICHECK_TMPDIR}
	COMMAND ${ABI_COPY_COMMAND} ../config.h ${ABICHECK_TMPDIR}/ ${ABI_COPY_FLAGS}
	COMMAND ${ABI_COPY_COMMAND} ${ABICHECK_HEADERS} ${ABICHECK_TMPDIR}/ ${ABI_COPY_FLAGS}
	COMMAND ${ABICHECK_COMMAND}
	COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps/libwiretap/libwiretap_* ${CMAKE_CURRENT_BINARY_DIR}/libwiretap.abi.tar.gz
	COMMAND rm -rf ${ABICHECK_TMPDIR} ${CMAKE_CURRENT_BINARY_DIR}/abi_dumps
	DEPENDS ${HEADERS} wiretap)

target_link_libraries(wiretap
	PUBLIC
		wsutil
		${GLIB2_LIBRARIES}
	PRIVATE
		${ZLIB_LIBRARIES}
)

target_include_directories(wiretap SYSTEM
	PRIVATE
		${ZLIB_INCLUDE_DIRS}
)

install(TARGETS wiretap
	EXPORT WiresharkTargets
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${WIRETAP_PUBLIC_HEADERS}
	DESTINATION "${PROJECT_INSTALL_INCLUDEDIR}/wiretap"
)

CHECKAPI(
	NAME
	  wiretap
	SWITCHES
	  --group abort:10 --summary-group abort
	  --group termoutput:1 --summary-group termoutput
	  --build
	SOURCES
	  ${WIRETAP_NONGENERATED_FILES}
# LEX files commented out due to use of malloc, free etc.
#	  ${LEX_FILES}
	  ${YACC_FILES}
)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
