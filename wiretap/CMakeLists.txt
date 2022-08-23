# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(WIRETAP_PUBLIC_HEADERS
	file_wrappers.h
	merge.h
	pcap-encap.h
	pcapng_module.h
	secrets-types.h
	wtap.h
	wtap_modules.h
	wtap_opttypes.h
)

#
# Files that implement reading and possibly writing one or more
# file types.  (For cases where more than one source file is
# used, this should be the one that contains a registration routine.)
#
# This does not include libpcap.c and pcapng.c; those are listed below,
# and we don't scan them to see whether they have registration
# routines, we *require* them to have registration routines named
# register_pcap() and register_pcapng(), and directly call those routines.
#
set(WIRETAP_C_MODULE_FILES
	${CMAKE_CURRENT_SOURCE_DIR}/5views.c
	${CMAKE_CURRENT_SOURCE_DIR}/aethra.c
	${CMAKE_CURRENT_SOURCE_DIR}/ascendtext.c
	${CMAKE_CURRENT_SOURCE_DIR}/atm.c
	${CMAKE_CURRENT_SOURCE_DIR}/autosar_dlt.c
	${CMAKE_CURRENT_SOURCE_DIR}/ber.c
	${CMAKE_CURRENT_SOURCE_DIR}/blf.c
	${CMAKE_CURRENT_SOURCE_DIR}/btsnoop.c
	${CMAKE_CURRENT_SOURCE_DIR}/busmaster.c
	${CMAKE_CURRENT_SOURCE_DIR}/camins.c
	${CMAKE_CURRENT_SOURCE_DIR}/candump.c
	${CMAKE_CURRENT_SOURCE_DIR}/capsa.c
	${CMAKE_CURRENT_SOURCE_DIR}/catapult_dct2000.c
	${CMAKE_CURRENT_SOURCE_DIR}/commview.c
	${CMAKE_CURRENT_SOURCE_DIR}/cosine.c
	${CMAKE_CURRENT_SOURCE_DIR}/csids.c
	${CMAKE_CURRENT_SOURCE_DIR}/daintree-sna.c
	${CMAKE_CURRENT_SOURCE_DIR}/dbs-etherwatch.c
	${CMAKE_CURRENT_SOURCE_DIR}/dpa400.c
	${CMAKE_CURRENT_SOURCE_DIR}/dct3trace.c
	${CMAKE_CURRENT_SOURCE_DIR}/erf.c
	${CMAKE_CURRENT_SOURCE_DIR}/eri_enb_log.c
	${CMAKE_CURRENT_SOURCE_DIR}/eyesdn.c
	${CMAKE_CURRENT_SOURCE_DIR}/hcidump.c
	${CMAKE_CURRENT_SOURCE_DIR}/i4btrace.c
	${CMAKE_CURRENT_SOURCE_DIR}/ipfix.c
	${CMAKE_CURRENT_SOURCE_DIR}/iptrace.c
	${CMAKE_CURRENT_SOURCE_DIR}/iseries.c
	${CMAKE_CURRENT_SOURCE_DIR}/json.c
	${CMAKE_CURRENT_SOURCE_DIR}/k12.c
	${CMAKE_CURRENT_SOURCE_DIR}/lanalyzer.c
	${CMAKE_CURRENT_SOURCE_DIR}/log3gpp.c
	${CMAKE_CURRENT_SOURCE_DIR}/logcat.c
	${CMAKE_CURRENT_SOURCE_DIR}/logcat_text.c
	${CMAKE_CURRENT_SOURCE_DIR}/mp4.c
	${CMAKE_CURRENT_SOURCE_DIR}/mpeg.c
	${CMAKE_CURRENT_SOURCE_DIR}/mplog.c
	${CMAKE_CURRENT_SOURCE_DIR}/mime_file.c
	${CMAKE_CURRENT_SOURCE_DIR}/mp2t.c
	${CMAKE_CURRENT_SOURCE_DIR}/netmon.c
	${CMAKE_CURRENT_SOURCE_DIR}/netscaler.c
	${CMAKE_CURRENT_SOURCE_DIR}/netscreen.c
	${CMAKE_CURRENT_SOURCE_DIR}/nettl.c
	${CMAKE_CURRENT_SOURCE_DIR}/nettrace_3gpp_32_423.c
	${CMAKE_CURRENT_SOURCE_DIR}/netxray.c
	${CMAKE_CURRENT_SOURCE_DIR}/ngsniffer.c
	${CMAKE_CURRENT_SOURCE_DIR}/observer.c
	${CMAKE_CURRENT_SOURCE_DIR}/packetlogger.c
	${CMAKE_CURRENT_SOURCE_DIR}/pcap-common.c
	${CMAKE_CURRENT_SOURCE_DIR}/peekclassic.c
	${CMAKE_CURRENT_SOURCE_DIR}/peektagged.c
	${CMAKE_CURRENT_SOURCE_DIR}/rfc7468.c
	${CMAKE_CURRENT_SOURCE_DIR}/pppdump.c
	${CMAKE_CURRENT_SOURCE_DIR}/radcom.c
	${CMAKE_CURRENT_SOURCE_DIR}/ruby_marshal.c
	${CMAKE_CURRENT_SOURCE_DIR}/snoop.c
	${CMAKE_CURRENT_SOURCE_DIR}/stanag4607.c
	${CMAKE_CURRENT_SOURCE_DIR}/systemd_journal.c
	${CMAKE_CURRENT_SOURCE_DIR}/tnef.c
	${CMAKE_CURRENT_SOURCE_DIR}/toshiba.c
	${CMAKE_CURRENT_SOURCE_DIR}/visual.c
	${CMAKE_CURRENT_SOURCE_DIR}/vms.c
	${CMAKE_CURRENT_SOURCE_DIR}/vwr.c
)

set(WIRETAP_LEX_MODULE_FILES
	${CMAKE_CURRENT_SOURCE_DIR}/k12text.l
)

#
# Files to scan for registration routines.
#
set(WIRETAP_MODULE_FILES
	${WIRETAP_C_MODULE_FILES}
	${WIRETAP_LEX_MODULE_FILES}
)

#
# C source files that aren't generated.
#
set(WIRETAP_NONGENERATED_C_FILES
	${WIRETAP_C_MODULE_FILES}
	${CMAKE_CURRENT_SOURCE_DIR}/pcapng.c
	${CMAKE_CURRENT_SOURCE_DIR}/libpcap.c
	${CMAKE_CURRENT_SOURCE_DIR}/file_access.c
	${CMAKE_CURRENT_SOURCE_DIR}/file_wrappers.c
	${CMAKE_CURRENT_SOURCE_DIR}/merge.c
	${CMAKE_CURRENT_SOURCE_DIR}/wtap.c
	${CMAKE_CURRENT_SOURCE_DIR}/wtap_opttypes.c
)

#
# All C files to compile.
#
set(WIRETAP_FILES ${WIRETAP_NONGENERATED_C_FILES} wtap_modules.c)

add_lex_files(LEX_FILES WIRETAP_FILES
	${WIRETAP_LEX_MODULE_FILES}
	${CMAKE_CURRENT_SOURCE_DIR}/ascend_scanner.l
	${CMAKE_CURRENT_SOURCE_DIR}/busmaster_scanner.l
	${CMAKE_CURRENT_SOURCE_DIR}/candump_scanner.l
)

add_lemon_files(LEMON_FILES WIRETAP_FILES
	${CMAKE_CURRENT_SOURCE_DIR}/ascend_parser.lemon
	${CMAKE_CURRENT_SOURCE_DIR}/busmaster_parser.lemon
	${CMAKE_CURRENT_SOURCE_DIR}/candump_parser.lemon
)

#
# We pass the arguments to make-regs.py in a file to avoid limitations
# with the number of arguments handled by main().
#
file(GENERATE
	OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/wtap_modules.in.txt"
	CONTENT "$<JOIN:${WIRETAP_MODULE_FILES},\n>\n"
)
add_custom_command(
	OUTPUT wtap_modules.c
	COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tools/make-regs.py wtap_modules wtap_modules.c @wtap_modules.in.txt
	DEPENDS ${CMAKE_SOURCE_DIR}/tools/make-regs.py ${WIRETAP_MODULE_FILES}
		"${CMAKE_CURRENT_BINARY_DIR}/wtap_modules.in.txt"
	COMMENT "Making wtap_modules.c"
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
	${CMAKE_BINARY_DIR}/resources/libwiretap.rc
)

set_target_properties(wiretap PROPERTIES
	PREFIX "lib"
	COMPILE_DEFINITIONS "WS_BUILD_DLL"
	LINK_FLAGS "${WS_LINK_FLAGS}"
	VERSION "0.0.0" SOVERSION 0
	FOLDER "DLLs"
	INSTALL_RPATH "${LIBRARY_INSTALL_RPATH}"
)
if(MSVC)
	set_target_properties(wiretap PROPERTIES LINK_FLAGS_DEBUG "${WS_MSVC_DEBUG_LINK_FLAGS}")
endif()

target_link_libraries(wiretap
	PUBLIC
		wsutil
	PRIVATE
		${ZLIB_LIBRARIES}
		${ZSTD_LIBRARIES}
		${LZ4_LIBRARIES}
)

target_include_directories(wiretap SYSTEM
	PRIVATE
		${ZLIB_INCLUDE_DIRS}
		${ZSTD_INCLUDE_DIRS}
		${LZ4_INCLUDE_DIRS}
)

target_include_directories(wiretap PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
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
	SOURCES
	  ${WIRETAP_NONGENERATED_FILES}
# LEX files commented out due to use of malloc, free etc.
#	  ${LEX_FILES}
	  ${LEMON_FILES}
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
